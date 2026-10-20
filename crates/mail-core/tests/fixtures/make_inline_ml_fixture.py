#!/usr/bin/env python3
"""Generate a minimal but valid inline-ML fixture for CI smoke tests.

Produces:
  model.onnx    — graph with `input_ids`/`attention_mask` int64 [1,128]
                  inputs and a constant `logits` float32 [1,13] output
                  (INLINE_ML_CLASS_COUNT=13, INLINE_ML_MAX_SEQUENCE=128).
  tokenizer.json — WordLevel tokenizer with [PAD]/[UNK]/[CLS]/[SEP]
                  matching the DistilBERT-style special-token contract
                  `OrtModelRuntime::load` requires ([PAD] must exist and
                  be id 0 for the fixed padding the runtime installs).

The fixture is NOT a trained model; it only proves the load path, the
tokenization contract and the logits shape end to end.
"""

import json
import sys
from pathlib import Path


def main() -> int:
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "inline-ml-fixture")
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        import numpy as np
        import onnx
        from onnx import TensorProto, helper, numpy_helper
    except ImportError:
        print("install: pip install onnx numpy", file=sys.stderr)
        return 2

    seq, classes = 128, 13
    input_ids = helper.make_tensor_value_info("input_ids", TensorProto.INT64, [1, seq])
    attention_mask = helper.make_tensor_value_info("attention_mask", TensorProto.INT64, [1, seq])
    logits_info = helper.make_tensor_value_info("logits", TensorProto.FLOAT, [1, classes])
    # Constant zero logits: sigmoid(0)=0.5 for every class — finite and in
    # (0,1), which satisfies the runtime's probability-range contract.
    bias = numpy_helper.from_array(np.zeros((1, classes), dtype=np.float32), "bias")
    constant = helper.make_node("Constant", [], ["logits"], value=bias)
    graph = helper.make_graph(
        [constant],
        "nullapart-ci-fixture",
        [input_ids, attention_mask],
        [logits_info],
    )
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 17)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    onnx.save(model, str(out_dir / "model.onnx"))

    tokenizer = {
        "version": "1.0",
        "truncation": None,
        "padding": None,
        "normalizer": None,
        "pre_tokenizer": {"type": "Whitespace"},
        "post_processor": None,
        "decoder": None,
        "model": {
            "type": "WordLevel",
            "vocab": {"[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3},
            "unk_token": "[UNK]",
        },
    }
    (out_dir / "tokenizer.json").write_text(json.dumps(tokenizer), encoding="utf-8")
    print(f"fixture written to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
