# Plan: InMemoryArtifactStore access-control + integrity remediation (slice 1)

## Scope

Allowed files only:

- `crates/mail-core/src/artifact_store.rs`
- `crates/mail-core/tests/artifact_store.rs`

Both are currently untracked new files. Grep confirms `ArtifactAccessContext` /
`InMemoryArtifactStore` / `delete_after_retention` are referenced nowhere else in
the workspace (only `crates/mail-core/src/lib.rs` declares `pub mod artifact_store;`),
so the API change cannot break any other uncommitted change
(`mail-contracts/finding.rs`, `scanner-sdk/*`, `infrastructure/*`, etc. stay untouched).

Context read: `SECURITY.md`, `docs/10-AWS-DATA-STORAGE.md` (ArtifactStore /
artifact-reference sections), `docs/security/24-BUSINESS-LOGIC-POLICY-SECURITY.md`,
`docs/engineering/CODE-STANDARDS.md`, `docs/16-BUILD-ROADMAP.md`,
`docs/phases/PHASE-2-SCANNER-FABRIC.md`, and both allowed files in full.

## Defects being repaired

1. **Access control**
   - `ArtifactAccessContext` carried only deployment/customer scope: no permission
     bits, no actor, no purpose. Any caller that could name a matching scope could
     read content.
   - `delete_after_retention(id)` performed **no grant or scope check at all**:
     once `retention_class == Deleted`, any caller in any deployment/customer could
     delete the artifact (cross-tenant delete).
2. **Integrity**
   - `put` never validated `artifact.size == bytes.len()`.
   - Hash algorithm/format were not validated distinctly: SHA-512, uppercase hex,
     wrong-length hex all collapsed into `HashMismatch` (or worse, only failed by
     accident of string comparison), and malformed declared metadata was
     indistinguishable from content-tamper.

## Explicit non-goals (this slice)

- No retention tombstones, no audit records.
- No URL/HTTP/S3 changes; `crates/mail-contracts/*` untouched.
- No new service/datastore/endpoint/dependency.
- Existing isolation/immutability/retention tests keep their strength.

## Implementation

### A. `crates/mail-core/src/artifact_store.rs`

1. **Remove** `ArtifactAccessContext`. **Add**:

   ```rust
   /// Closed set of server-side purposes for an artifact access grant.
   #[derive(Debug, Clone, Copy, PartialEq, Eq)]
   pub enum ArtifactAccessPurpose {
       Scanner,
       QuarantineRelease,
       RetentionWorker,
   }

   /// Server-issued access grant for artifact read/delete operations.
   ///
   /// Constructing this type is an internal test/development seam only;
   /// real callers obtain it only after server-side authorization.
   #[derive(Debug, Clone, PartialEq, Eq)]
   pub struct ArtifactAccessGrant {
       pub deployment_id: DeploymentId,
       pub customer_id: Option<CustomerId>,
       pub actor_id: String,
       pub can_read_content: bool,
       pub can_delete: bool,
       pub purpose: ArtifactAccessPurpose,
   }
   ```

   (Rustdoc wording on the grant must state the test/development-seam +
   server-authorization fact as above.)

2. **New error variant** on `ArtifactStoreError`:

   ```rust
   #[error("artifact metadata invalid")]
   InvalidMetadata,
   ```

3. **Private scope helper** preserving current get semantics for both operations:
   deployment must equal `stored.artifact.deployment_id`; if the stored artifact
   has `Some(customer_id)`, the grant must carry the same customer; artifacts with
   `customer_id: None` match any grant in the same deployment.

4. **`get(&self, grant: &ArtifactAccessGrant, id: &ArtifactId)`**
   - `!grant.can_read_content` → `NotFound` (checked before lookup, no lock needed).
   - missing id → `NotFound`.
   - scope mismatch → `NotFound` (existence not revealed across scopes).

5. **`delete_after_retention(&self, grant: &ArtifactAccessGrant, id: &ArtifactId)`**
   - `!grant.can_delete` → `NotFound` (before lookup).
   - missing id → `NotFound`.
   - scope mismatch → `NotFound` (**before** the retention check, so wrong-scope
     callers cannot learn retention state).
   - `retention_class != Deleted` → `RetentionViolation` (unchanged).
   - else remove → `Ok(())`.

6. **`put` validation order** (before taking the write lock):

   1. `artifact.size != bytes.len() as u64` → `InvalidMetadata`.
   2. `hash.algorithm != Sha256` (covers SHA-512/MD5) → `InvalidMetadata`.
   3. hash value not canonical lowercase 64-char hex (length 64, ASCII hex digits,
      no uppercase) → `InvalidMetadata`.
   4. well-formed value ≠ `hex::encode(Sha256::digest(bytes))` → `HashMismatch`.

   Consistent rule: **`InvalidMetadata` = declared metadata malformed/unsupported;
   `HashMismatch` = well-formed SHA-256 of different content.**

7. Unchanged: `StoredArtifact`, idempotent-duplicate/`ImmutableConflict` logic,
   `RetentionViolation`, `same_metadata` / `same_storage_location`, module-level
   rustdoc updated to mention grant-based access.

### B. `crates/mail-core/tests/artifact_store.rs`

1. Replace `access_context(...)` helper with a `grant(...)` helper building a
   full-permission `ArtifactAccessGrant` (`actor_id: "test-actor"`,
   `purpose: ArtifactAccessPurpose::Scanner`); negatives built by mutating fields.
2. Adjust all 7 existing tests to pass grants (wrong-deployment/wrong-customer get
   tests use **full-permission** grants so `NotFound` proves scope enforcement, not
   permission denial). No existing assertion weakened.
3. New tests:
   - `get_without_read_permission_is_not_found` — `can_read_content: false`,
     matching scope → `NotFound`.
   - `delete_without_delete_permission_is_not_found` — `Deleted`-class artifact,
     `can_delete: false` → `NotFound`, then still readable with a read grant
     (proves it was not removed).
   - `delete_with_wrong_customer_scope_is_not_found` — `Deleted`-class artifact for
     CUSTOMER_ONE, grant for CUSTOMER_TWO (full permissions) → `NotFound`, artifact
     still present (without the scope check the delete would succeed).
   - `delete_with_wrong_deployment_scope_is_not_found` — same pattern with
     DEPLOYMENT_B → `NotFound`, artifact still present.
   - `put_rejects_declared_size_mismatch` → `InvalidMetadata`; `get` afterwards →
     `NotFound` (rejected put stores nothing).
   - `put_rejects_sha512_algorithm` → `InvalidMetadata` (size correct so hash
     validation is reached).
   - `put_rejects_uppercase_sha256_hash` → `InvalidMetadata` (uppercase of the
     correct digest, caught by format check before digest comparison).
4. Update the test-file module doc to describe grant-based access + metadata
   validation coverage.

Total: 7 adjusted + 7 new = 14 tests.

## Verification (required commands, in order)

1. `cargo fmt --all -- --check` (if it fails, run `cargo fmt --all` then re-check).
2. `cargo test -p nullapart-mail-core --test artifact_store`.
3. `git diff --check`.

Note: the two allowed files are untracked, so `git diff --check` only covers other
tracked modifications; formatting of the new files is covered by `cargo fmt --check`
and compilation by the test run.

## Final response will list

- Behavior changes (grant model, NotFound semantics, put validation, `InvalidMetadata`).
- Tests: names of adjusted and new tests plus the three verification command results.
