"""Export the trained checkpoint to ONNX, quantize to int8, verify parity.

Fixed batch=1 / sequence=128 graph (plan decision 16 latency target),
int8 dynamic quantization with artifact-size and p95 latency checks,
export report written next to the models.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
from onnxruntime import SessionOptions
from onnxruntime.quantization import QuantType, quantize_dynamic
from transformers import DistilBertForSequenceClassification, DistilBertTokenizerFast

ROOT = Path(__file__).resolve().parent
CHECKPOINTS = ROOT / "checkpoints" / "multilabel-v1"
ONNX_DIR = CHECKPOINTS / "onnx"

TARGETS = {
    "latency_p95_ms_max": 50.0,
    "artifact_mb_max": 100.0,
    "parity_min_mean_abs_diff": 0.05,
}


class LogitsWrapper(torch.nn.Module):
    def __init__(self, model) -> None:
        super().__init__()
        self.model = model

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        return self.model(input_ids=input_ids, attention_mask=attention_mask).logits


def percentile(values: list[float], q: float) -> float:
    return round(float(np.percentile(np.asarray(values), q)), 2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Export Inline ML checkpoint to ONNX")
    parser.add_argument("--checkpoint", default=str(CHECKPOINTS / "model"))
    parser.add_argument("--opset", type=int, default=17)
    parser.add_argument("--latency-iters", type=int, default=300)
    args = parser.parse_args()

    import onnxruntime

    ONNX_DIR.mkdir(parents=True, exist_ok=True)
    fp32_path = ONNX_DIR / "model.onnx"
    int8_path = ONNX_DIR / "model_int8.onnx"

    model = DistilBertForSequenceClassification.from_pretrained(args.checkpoint)
    model.eval()
    wrapper = LogitsWrapper(model)
    wrapper.eval()

    input_ids = torch.zeros((1, 128), dtype=torch.long)
    attention_mask = torch.ones((1, 128), dtype=torch.long)
    torch.onnx.export(
        wrapper,
        (input_ids, attention_mask),
        str(fp32_path),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        opset_version=args.opset,
        do_constant_folding=True,
        # The dynamo exporter's graph fails onnxruntime's quantizer shape
        # inference ("768 vs 13"); the TorchScript exporter produces the
        # classic DistilBERT graph dynamic quantization expects.
        dynamo=False,
    )

    quantize_dynamic(
        model_input=str(fp32_path),
        model_output=str(int8_path),
        weight_type=QuantType.QInt8,
    )

    tokenizer = DistilBertTokenizerFast.from_pretrained(args.checkpoint)
    sample = (
        "Subject: urgent wire request\nFrom: cfo@example.test\n"
        "Authentication-Results: mx.example.test; spf=fail\n"
        "Please process the transfer today."
    )
    encoded = tokenizer(
        sample,
        truncation=True,
        max_length=128,
        padding="max_length",
        return_tensors="pt",
    )
    with torch.no_grad():
        torch_logits = (
            model(input_ids=encoded["input_ids"], attention_mask=encoded["attention_mask"])
            .logits
            .numpy()
        )
    torch_probs = 1.0 / (1.0 + np.exp(-np.clip(torch_logits, -50, 50)))

    parity = {}
    for name, path in (("fp32", fp32_path), ("int8", int8_path)):
        session = onnxruntime.InferenceSession(str(path), providers=["CPUExecutionProvider"])
        feed = {
            "input_ids": encoded["input_ids"].numpy(),
            "attention_mask": encoded["attention_mask"].numpy(),
        }
        out = session.run(None, feed)[0]
        probs = 1.0 / (1.0 + np.exp(-np.clip(out, -50, 50)))
        parity[name] = {
            "mean_abs_diff": round(float(np.abs(probs - torch_probs).mean()), 5),
            "max_abs_diff": round(float(np.abs(probs - torch_probs).max()), 5),
            "argmax_agree": bool(int(np.argmax(probs)) == int(np.argmax(torch_probs))),
        }

    bench_session = onnxruntime.InferenceSession(
        str(int8_path),
        providers=["CPUExecutionProvider"],
        sess_options=SessionOptions(),
    )
    durations = []
    for i in range(args.latency_iters + 30):
        started = time.perf_counter()
        bench_session.run(None, feed)
        if i >= 30:
            durations.append((time.perf_counter() - started) * 1000.0)

    sizes = {
        "fp32_mb": round(fp32_path.stat().st_size / (1024 * 1024), 2),
        "int8_mb": round(int8_path.stat().st_size / (1024 * 1024), 2),
    }
    report = {
        "opset": args.opset,
        "input": {"batch": 1, "seq_len": 128},
        "sizes": sizes,
        "parity": parity,
        "latency_cpu_int8": {
            "iterations": args.latency_iters,
            "p50_ms": percentile(durations, 50),
            "p95_ms": percentile(durations, 95),
            "mean_ms": round(float(np.mean(durations)), 2),
        },
        "targets": TARGETS,
        "targets_met": {
            "int8_size_le_100mb": sizes["int8_mb"] <= TARGETS["artifact_mb_max"],
            "p95_le_50ms": percentile(durations, 95) <= TARGETS["latency_p95_ms_max"],
            "int8_parity": parity["int8"]["mean_abs_diff"]
            <= TARGETS["parity_min_mean_abs_diff"],
        },
    }
    out = CHECKPOINTS / "export_report.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
