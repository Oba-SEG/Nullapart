# Private Outbound DKIM Signing Runbook

**Status:** local/dev and deployment procedure. This runbook does not mark a
deployment as production SMTP-ready; `docs/21-AWS-SMTP-COMMISSIONING.md`
remains the production gate.

## Security boundary

Customer outbound mail reaches the signer only through the Mail Core private
submission path and Postfix listener on port `10027`. That listener is not
published to the host and permits only the Mail Core container IP. Rspamd signs
only that source with a per-domain key selected from runtime maps.

The separate quarantine-reinjection listener on port `10026` explicitly
disables the Rspamd milter. It must not re-filter or sign released inbound
messages, even though its authorized Mail Core source IP is the same.

Every delivery worker must make a durable, transaction-scoped idempotency claim
before the SMTP attempt and record the Postfix queue identifier after `250`.
If the final response or ledger record is ambiguous, retain the claim for
recovery and defer; never retry the SMTP transaction blindly.

Do not send a private key through Git, a Docker image layer, the frontend,
Mail Core configuration, logs, a ticket, or this runbook. The tracked
`infrastructure/containers/dkim-unconfigured/` directory is intentionally
keyless and contains only empty map templates. `.gitignore` rejects its
`keys/` subtree as a second guardrail.

## Provision a domain key

1. Generate and store the private key using the approved deployment secret
   boundary. For local/dev on `192.168.8.4`, use a host directory that is not
   inside the repository, for example
   `/home/ob1/.local/share/nullapart/dkim-dev`.
2. Give the mounted directory and `keys/` directory mode `0700`; give the map
   and key files mode `0640`; make them readable only by the Rspamd container
   identity. Do not relax permissions to debug a mount.
3. Write one entry for every authorized sending domain to `selectors.map`:

   ```text
   customer.example selector2026a
   ```

4. Write the matching path entry to `paths.map`:

   ```text
   customer.example /run/nullapart/dkim/keys/customer.example.selector2026a.key
   ```

5. Set `NULLAPART_DKIM_KEY_DIR` only in the deployment environment file to
   that secret directory, then recreate the Rspamd container. The compose
   fallback contains no keys, so an unset variable fails closed without
   signing.
6. Publish the matching selector TXT record, authorize the commissioned egress
   in SPF, and confirm aligned DMARC. BIMI may be observed only as DNS metadata
   until its SVG and certificate validation are implemented safely.

## Verify without exposing content or keys

1. Run `rspamadm configtest` in the Rspamd container.
2. Submit a non-sensitive test message from the Mail Core workload to the
   private `postfix:10027` listener with matching envelope and `From` domains.
3. Hold the test recipient temporarily if needed and inspect the queued
   message only inside Postfix for a `DKIM-Signature` with the expected domain
   and selector. Delete the test queue entry afterwards.
4. Verify that a different container cannot relay through port `10027`, and
   that an inbound or quarantine-reinjection path does not acquire a signature.
5. For production, complete an external received-message verification and
   record DNS/SPF/DMARC evidence in the commissioning record.

## Rotate or revoke

1. Provision a new key and selector alongside the old one.
2. Publish the new TXT record and wait for DNS visibility.
3. Change both runtime maps atomically, recreate Rspamd, and verify a newly
   signed message uses the new selector.
4. Retain the old public DNS key for the agreed verification overlap. Remove
   the old private key only after queued messages and overlap requirements are
   satisfied.
5. On suspected compromise, remove the affected map entries, restart Rspamd to
   stop new signatures, rotate the key, and follow the incident process in
   `docs/security/04-INCIDENT-RESPONSE.md`.
