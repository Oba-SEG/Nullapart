# Container Infrastructure

Local/dev container evidence is reconciled against the authoritative Phase 0/1
plans in
[docs/reviews/2026-10-13-phase-0-1-conformance.md](../../docs/reviews/2026-10-13-phase-0-1-conformance.md).
Do not treat a successful local container run as AWS SMTP commissioning or
production readiness evidence.

## Orchestration

Amazon ECS is the initial baseline for ordinary Nullapart application/worker/scanner containers.

Use capacity providers so workloads can use Fargate or EC2-backed capacity according to resource/isolation needs.

EKS/Kubernetes is not the default and requires a demonstrated architecture need.

Dedicated mail EC2 nodes are an intentional exception where stable EIP/PTR identity, durable Postfix queueing and controlled MTA draining matter more than generic task mobility.

## Image requirements

Images are:

- minimal;
- pinned;
- immutable by digest in production;
- non-root where practical;
- scanned;
- SBOM-tracked;
- free of embedded secrets;
- explicit about writable paths;
- explicit about capabilities;
- explicit about CPU/RAM/temp storage.

High-risk parsers receive stronger isolation.

## Patching

Do not patch running containers interactively.

Rebuild from patched dependencies/base images, test and promote a new immutable digest.

See:

- `docs/24-CONTAINER-LOADBALANCING-NETWORK.md`
- `docs/security/23-PATCHING-DEPENDENCY-VERSIONS.md`
