# Nullapart Architecture Diagrams

Mermaid is the canonical diagram source format for Nullapart architecture. The source files live beside this index so diagrams remain diffable and reviewable in Git.

## 1. System context

Source: [00-system-context.mmd](00-system-context.mmd)

```mermaid
flowchart LR
    Internet((Internet))
    CustomerMail[Customer Mail Systems]
    Admins[System / Support / Customer Admins]

    subgraph Deployment["Nullapart Regional Deployment"]
        subgraph MailPlane["Mail Plane"]
            Postfix[Postfix SMTP]
            Rspamd[Rspamd]
            MailCore[Rust Mail Core]
            Scanners[Scanner Fabric]
            InlineML[Inline ML]
            Policy[Policy Runtime]
            Quarantine[Quarantine]
        end

        subgraph ControlPlane["Control Plane"]
            UI[Neumorphic Admin UI]
            Control[Control Backend]
            Identity[ZITADEL]
            Config[(PostgreSQL)]
            Cache[(Redis)]
            Secrets[OpenBao]
        end

        subgraph Intelligence["Intelligence / Operations"]
            DMARC[DMARC + BIMI]
            DeepAI[Regional Deep AI]
            Events[Durable Events]
            N8N[n8n]
            ClickUp[ClickUp]
            Notify[Notifications]
        end

        Artifacts[(S3 Artifact Store)]
    end

    Internet --> Postfix
    CustomerMail <--> Postfix
    Postfix --> Rspamd --> MailCore
    MailCore --> Scanners
    MailCore --> InlineML
    MailCore --> Policy
    Policy --> Quarantine
    MailCore --> Artifacts

    Admins --> UI --> Control
    Control --> Identity
    Control --> Config
    Control --> Cache
    Control --> Secrets

    MailCore --> Events
    Events --> DMARC
    Events --> DeepAI
    Events --> N8N --> ClickUp
    Events --> Notify
```

## 2. Inbound mail flow

Source: [01-inbound-mail-flow.mmd](01-inbound-mail-flow.mmd)

```mermaid
flowchart TD
    Sender[External SMTP Sender]
    Restrict[Postfix SMTP Restriction Stage]
    Milter[Rspamd Milter Stage]
    Queue[(Postfix Durable Queue)]
    Normalize[MIME Normalization]
    Fanout{Parallel Security Analysis}
    Malware[Malware Scanner]
    URL[URL / Domain Scanner]
    Docs[Document / Archive Scanner]
    OCR[OCR / QR / Image]
    Static[Static / YARA]
    ML[Inline ML]
    Policy[Policy Evaluation]
    Deliver[Deliver to Customer]
    Quarantine[Quarantine]
    Hold[Hold]
    Reject[SMTP Reject]
    Defer[SMTP Defer]

    Sender --> Restrict
    Restrict -->|Reject condition| Reject
    Restrict -->|Temporary failure| Defer
    Restrict -->|Continue| Milter
    Milter --> Queue
    Queue --> Normalize --> Fanout

    Fanout --> Malware
    Fanout --> URL
    Fanout --> Docs
    Fanout --> OCR
    Fanout --> Static

    Malware --> ML
    URL --> ML
    Docs --> ML
    OCR --> ML
    Static --> ML

    ML --> Policy
    Policy -->|Allow / Warn| Deliver
    Policy -->|Quarantine| Quarantine
    Policy -->|Hold / Deep Analysis| Hold
```

## 3. Outbound mail flow

Source: [02-outbound-mail-flow.mmd](02-outbound-mail-flow.mmd)

```mermaid
flowchart TD
    Customer[Customer Mail System]
    Postfix[Postfix Outbound]
    Tenant[Identify Tenant / Trusted Source]
    Domain[Validate Sending Domain]
    Bulk[Bulk / Rate / Abuse Controls]
    Queue[(Durable Queue)]
    Scan[Security Scanner Fabric]
    Behaviour[Outbound Behaviour Analysis]
    Policy[Outbound Policy]
    Signing[DKIM / Transport Controls]
    Route{Route}
    Smart[Smart Host]
    Direct[Direct MX]
    Block[Block / Reject]
    Defer[Defer / Throttle / Hold]
    Internet((Internet))

    Customer --> Postfix --> Tenant
    Tenant -->|Unauthorized| Block
    Tenant --> Domain
    Domain -->|Domain not INTERNAL or approved SEND_ONLY| Block
    Domain --> Bulk
    Bulk -->|Abuse / Unapproved bulk| Defer
    Bulk --> Queue --> Scan --> Behaviour --> Policy
    Policy -->|Block| Block
    Policy -->|Defer / Throttle / Hold| Defer
    Policy -->|Allow| Signing --> Route
    Route --> Smart --> Internet
    Route --> Direct --> Internet
```

## 4. Regional AWS topology

Source: [03-regional-aws-topology.mmd](03-regional-aws-topology.mmd)

```mermaid
flowchart TB
    Login[nullapart.com Login / Region Selector]

    subgraph ZA["ZA Deployment"]
        ZAWeb[za.nullapart.com]
        ZAMX[mx1 / mx2.za.nullapart.com]
        ZAApp[Control + Mail Runtime]
        ZADB[(PostgreSQL)]
        ZARedis[(Redis)]
        ZAS3[(S3)]
        ZAID[ZITADEL]
        ZAVault[OpenBao]
        ZAAI[Regional Deep AI]
    end

    subgraph ZAB["ZAB Deployment"]
        ZABWeb[zab.nullapart.com]
        ZABMX[mx1 / mx2.zab.nullapart.com]
        ZABApp[Control + Mail Runtime]
        ZABDB[(PostgreSQL)]
        ZABRedis[(Redis)]
        ZABS3[(S3)]
        ZABID[ZITADEL]
        ZABVault[OpenBao]
        ZABAI[Regional Deep AI]
    end

    subgraph EU["EU Deployment"]
        EUWeb[eu.nullapart.com]
        EUMX[mx1 / mx2.eu.nullapart.com]
        EUApp[Control + Mail Runtime]
        EUDB[(PostgreSQL)]
        EURedis[(Redis)]
        EUS3[(S3)]
        EUID[ZITADEL]
        EUVault[OpenBao]
        EUAI[Regional Deep AI]
    end

    Login --> ZAWeb
    Login --> ZABWeb
    Login --> EUWeb

    ZAWeb --> ZAApp
    ZAMX --> ZAApp
    ZAApp --> ZADB
    ZAApp --> ZARedis
    ZAApp --> ZAS3
    ZAApp --> ZAID
    ZAApp --> ZAVault
    ZAApp --> ZAAI

    ZABWeb --> ZABApp
    ZABMX --> ZABApp
    ZABApp --> ZABDB
    ZABApp --> ZABRedis
    ZABApp --> ZABS3
    ZABApp --> ZABID
    ZABApp --> ZABVault
    ZABApp --> ZABAI

    EUWeb --> EUApp
    EUMX --> EUApp
    EUApp --> EUDB
    EUApp --> EURedis
    EUApp --> EUS3
    EUApp --> EUID
    EUApp --> EUVault
    EUApp --> EUAI

    ZA -. no customer-data federation .- ZAB
    ZAB -. no customer-data federation .- EU
```

## 5. Control-plane RBAC and impersonation

Source: [04-control-plane-rbac.mmd](04-control-plane-rbac.mmd)

```mermaid
flowchart TB
    System[System Admin]
    Support[Support Admin]
    Owner[Customer Owner / Admin]
    Roles[Customer RBAC Roles]

    IDP[ZITADEL]
    Backend[Nullapart Control Backend]
    Audit[(Audit Log)]

    SystemPolicies[System Policies]
    SupportPolicies[Support Policies]
    CustomerPolicies[Customer Policies]
    Sensitive[Message Content / Quarantine / Remediation]

    System --> IDP
    Support --> IDP
    Owner --> IDP
    Roles --> IDP

    IDP --> Backend

    Backend --> SystemPolicies
    Backend --> SupportPolicies
    Backend --> CustomerPolicies
    Backend --> Sensitive

    System -. full administration .-> SystemPolicies
    System -. full administration .-> SupportPolicies
    System -. full administration .-> CustomerPolicies

    Support -. permitted .-> SupportPolicies
    Support -. permitted .-> CustomerPolicies
    Support -. no body / attachment content .-> Sensitive

    Owner -. tenant scope .-> CustomerPolicies
    Owner -. assigns tenant permissions .-> Roles
    Roles -. RBAC controlled .-> Sensitive

    System -->|audited impersonation| Backend
    Support -->|audited impersonation| Backend
    Backend --> Audit
```

## 6. Scanner fabric

Source: [05-scanner-fabric.mmd](05-scanner-fabric.mmd)

```mermaid
flowchart LR
    MailCore[Rust Mail Core]
    Orchestrator[Scanner Orchestration]

    subgraph ScannerFabric["Expandable Scanner Fabric"]
        Malware[Malware]
        Static[Static / YARA]
        URL[URL / Domain]
        Archive[Archive]
        PDF[PDF]
        Office[Office / Document]
        Type[File Type Verification]
        OCR[OCR]
        QR[QR / Image]
        Future[Future Sandbox / TI]
    end

    Findings[SecurityFinding Aggregator]
    ML[Inline ML]
    Policy[Policy Runtime]

    MailCore --> Orchestrator
    Orchestrator --> Malware
    Orchestrator --> Static
    Orchestrator --> URL
    Orchestrator --> Archive
    Orchestrator --> PDF
    Orchestrator --> Office
    Orchestrator --> Type
    Orchestrator --> OCR
    Orchestrator --> QR
    Orchestrator -. optional .-> Future

    Malware --> Findings
    Static --> Findings
    URL --> Findings
    Archive --> Findings
    PDF --> Findings
    Office --> Findings
    Type --> Findings
    OCR --> Findings
    QR --> Findings
    Future --> Findings

    Findings --> ML --> Policy
```

## 7. Data and storage flow

Source: [06-data-storage-flow.mmd](06-data-storage-flow.mmd)

```mermaid
flowchart TB
    Control[Control Backend]
    MailCore[Mail Core]
    Scanners[Scanner Nodes]
    DeepAI[Deep AI]
    DMARC[DMARC / BIMI]
    Events[Event Consumers]

    PG[(PostgreSQL\nSource of Truth)]
    Redis[(Redis\nCache / Streams / Counters)]
    S3[(Amazon S3\nArtifacts / Quarantine)]
    Queue[(Postfix Queue)]
    KMS[AWS KMS]
    Bao[OpenBao]

    Control --> PG
    Control --> Redis

    MailCore --> PG
    MailCore --> Redis
    MailCore --> Queue
    MailCore --> S3

    Scanners --> S3
    Scanners --> Redis

    DeepAI -->|scoped eligible artifacts| S3
    DMARC --> PG
    Events --> Redis

    KMS --> S3
    KMS --> PG
    Bao --> Control
    Bao --> MailCore
    Bao --> Scanners
    Bao --> DeepAI
```

## 8. Event and operations flow

Source: [07-event-operations-flow.mmd](07-event-operations-flow.mmd)

```mermaid
flowchart LR
    Mail[Mail Plane]
    Control[Control Plane]
    DMARC[DMARC / BIMI]
    Outbound[Outbound Intelligence]
    DeepAI[Deep AI]

    Streams[(Durable Event Stream)]

    Notify[Customer Notifications]
    N8N[n8n]
    ClickUp[ClickUp]
    Sentry[Sentry]
    Logs[SegLumberjack / CloudWatch]
    Analytics[Reporting / Analytics]

    Mail --> Streams
    Control --> Streams
    DMARC --> Streams
    Outbound --> Streams
    DeepAI --> Streams

    Streams --> Notify
    Streams --> N8N --> ClickUp
    Streams --> Analytics

    Mail --> Sentry
    Control --> Sentry
    DeepAI --> Sentry

    Mail --> Logs
    Control --> Logs
    DMARC --> Logs
    Outbound --> Logs
```

## 9. Deep AI flow

Source: [08-deep-ai-flow.mmd](08-deep-ai-flow.mmd)

```mermaid
flowchart TD
    Eligible{Eligible Security Case?}
    Quarantine[Quarantined]
    Blocked[Blocked]
    Reported[Reported]
    Held[Held for Deep Analysis]
    Review[False Positive / Negative Review]

    Broker[Scoped Artifact Access / AI Broker]
    API[Authenticated OpenAI-Compatible API]
    Model[Regional Qwen3.8-27B Candidate]
    Result[Structured Deep-AI Finding]
    Policy[Policy / Authorized Human]
    Action[Disposition / Remediation / Case Update]

    Quarantine --> Eligible
    Blocked --> Eligible
    Reported --> Eligible
    Held --> Eligible
    Review --> Eligible

    Eligible -->|Yes| Broker
    Broker --> API --> Model --> Result
    Result --> Policy --> Action

    Eligible -->|No| Stop[No Deep-AI Content Access]
```

## 10. Security trust boundaries

Source: [09-trust-boundaries.mmd](09-trust-boundaries.mmd)

```mermaid
flowchart TB
    Internet((Public Internet))
    Customer[Customer Mail Systems]
    Admin[Administrators]

    subgraph PublicEdge["Public / Edge Boundary"]
        SMTP[Postfix SMTP]
        Web[Regional Web Entry]
    end

    subgraph PrivateApp["Private Application Boundary"]
        Rspamd[Rspamd]
        MailCore[Mail Core]
        Scanners[Scanner Nodes]
        Control[Control Backend]
        IDP[ZITADEL]
        N8N[n8n]
    end

    subgraph DataBoundary["Regional Data Boundary"]
        PG[(PostgreSQL)]
        Redis[(Redis)]
        S3[(S3)]
        Secrets[OpenBao]
    end

    subgraph AIBoundary["Regional AI Boundary"]
        AIGateway[Authenticated AI Endpoint]
        Model[Deep AI Model]
    end

    subgraph ExternalOps["External / Operational Integrations"]
        Sentry[Sentry]
        ClickUp[ClickUp]
        TI[Threat Intelligence]
    end

    Internet --> SMTP
    Customer <--> SMTP
    Admin --> Web

    SMTP --> Rspamd --> MailCore
    Web --> Control
    Control --> IDP

    MailCore --> Scanners
    MailCore --> PG
    MailCore --> Redis
    MailCore --> S3
    Control --> PG
    Control --> Redis

    Secrets --> MailCore
    Secrets --> Scanners
    Secrets --> Control

    MailCore --> AIGateway --> Model
    Model --> S3

    PrivateApp -->|sanitized / classified only| Sentry
    N8N -->|minimized metadata only| ClickUp
    Scanners -->|explicit allowed fields only| TI
```

## Diagram rules

- Mermaid sources are architecture artifacts and must be updated with architectural changes.
- Product-facing diagrams should avoid exposing unnecessary implementation details when used outside internal documentation.
- Security/trust-boundary diagrams must be reviewed when adding a new integration, public endpoint, scanner type, data store or cross-region flow.
- AWS-specific deployment details can evolve without changing the logical system-context diagram unless the logical trust/data boundaries change.
