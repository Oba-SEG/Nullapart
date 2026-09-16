# Abuse and Misuse Response

## Threats

Nullapart can be abused by compromised customer accounts, malicious tenants, bulk spammers, phishers, malware distributors, relay abuse and reputation attacks.

## Detection

Monitor outbound volume/fanout, new-recipient rate, complaint/bounce patterns, authentication/source anomalies, repeated policy blocks, malicious URL/attachment detections and rapid bulk-pattern changes.

## Actions

Policy may throttle, defer, hold, block sender/address/source, disable outbound relay or suspend tenant outbound service.

Actions are auditable and scoped.

## Malicious tenant

System/Support must be able to contain a deliberately abusive tenant without affecting unrelated tenants.

## Reputation incident

Runbook includes stopping offending traffic, identifying source/customer, evidence preservation, credential compromise checks, blocklist/reputation assessment, customer communication and cautious reputation recovery.

## False positives

Abuse controls require customer/support review paths so legitimate bulk senders can be corrected without weakening global security.
