# Security Testing and Penetration Testing

## Continuous testing

Automated security tests include:

- tenant isolation;
- authenticated-principal filtering;
- resource ownership/BOLA/IDOR;
- PostgreSQL RLS bypass and pooled-connection tenant-context leakage;
- RBAC/IDOR;
- impersonation constraints;
- audit completeness;
- CSRF;
- stored/reflected XSS;
- hostile email HTML/SVG;
- SSRF;
- OAST for blind SSRF/XXE/unintended callbacks;
- DNS rebinding/redirect revalidation where outbound fetch exists;
- path traversal;
- artifact authorization;
- MIME/parser fuzzing;
- archive/decompression bombs;
- malformed Office/PDF/images;
- SMTP relay abuse;
- SMTP loops/backscatter;
- header/authentication forgery;
- queue exhaustion;
- secret leakage;
- observability leakage;
- mass assignment;
- unsafe error disclosure;
- idempotency/replay failures;
- browser token persistence checks;
- CSRF;
- AI prompt injection/tool abuse.

## OAST

Use controlled out-of-band application security testing for features that can trigger server-side network activity.

Relevant tests include blind SSRF, XXE/external references and unexpected DNS/HTTP callbacks from URL scanners, report parsers, document processors, webhook handlers, remote-resource proxies and future AI tools.

OAST infrastructure is test-controlled and must not receive production secrets/customer content.

## Fuzzing

Prioritize MIME parsing, message normalization, archive/document parsing, scanner protocol adapters and internal SMTP/filter interfaces.

## External penetration tests

Conduct independent testing before major production launch, after material security-boundary changes and periodically thereafter.

## Findings

Findings enter vulnerability management and are tracked to closure.

## Tenant-isolation gate

Any cross-tenant data/control finding is release-blocking until remediated or explicitly contained with executive/security approval.

## AI evaluation

Deep AI testing covers prompt injection, adversarial attachments/images, data leakage, unauthorized artifact retrieval, tool abuse and malicious training-data candidates.
