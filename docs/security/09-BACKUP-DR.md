# Backup, Restore and Disaster Recovery

## Principle

A backup strategy is incomplete until restoration is tested.

## Systems

Define backup/recovery for:

- PostgreSQL;
- Admin Audit Store;
- S3/quarantine/artifacts;
- OpenBao configuration/storage/recovery material;
- ZITADEL data;
- critical DNS/IaC/configuration;
- n8n workflows;
- model/config artifacts;
- signing/PKI material according to key-custody rules.

Redis/Valkey cache is normally rebuildable and is not authoritative configuration storage.

## RPO/RTO

Define RPO and RTO per subsystem before production.

Mail queue recovery requirements differ from analytics/reporting and must be documented separately.

## Regionality

Backups respect residency. Cross-region replication is not enabled by convenience where it violates customer/regulatory constraints.

## Restore testing

Perform scheduled restore exercises covering database point-in-time restore, application/config reconstruction, audit integrity, S3 artifact recovery, OpenBao recovery, identity recovery and DNS/mail commissioning recovery.

## Disaster scenarios

Cover node loss, AZ loss, database failure, regional service degradation, credential/key loss, S3 accidental deletion/exposure, control-plane loss and mail-plane partial outage.

## Evidence

Record restore-test date, scope, result, gaps and corrective actions.
