/**
 * Write capabilities computed by the server and published with the payload that
 * renders them.
 *
 * The console never re-derives a gate from role or permission names: the same
 * predicate that `authorize` runs produces these fields, so an action shown as
 * available is one the API will accept, and an action withheld comes with the
 * reason the API applied. This is the customer-side shape of what policies
 * publish as `caller_tier` and features publish as `allowed_override_scopes`.
 */

import { permissionCapabilityLabel } from "../lib/labels";

/** Which gate refused the write. Mirrors `Blocker` in `crates/mail-core/src/admin_capabilities.rs`. */
export type CapabilityBlocker = "permission" | "lifecycle" | "deployment" | "role";

export interface WriteCapability {
  allowed: boolean;
  blocker: CapabilityBlocker | null;
}

export interface CustomerCapabilities {
  create_customer: WriteCapability;
  change_lifecycle: WriteCapability;
  add_send_only_domain: WriteCapability;
}

/**
 * Why `subject` is unavailable, in the operator's terms. Returns `null` when the
 * server says the action is allowed (or has not published a capability yet, in
 * which case the caller keeps its existing local check rather than inventing a
 * refusal the API may not apply).
 *
 * `permission` names the key the owning route enforces. A lock quotes what that
 * key lets someone do rather than the key itself, because the key belongs to the
 * platform's authorization table and the operator only needs the capability.
 * `roleRefusal`
 * replaces the whole `role` sentence where the reserved identity is not the
 * customer-identity pair — a gate named wrongly is a refusal nobody can act on.
 */
/** A capability label is written as a control would be ("Manage your
 *  administrators"); mid-sentence it names the thing, so the lead loses its
 *  capital. */
function lowerFirst(label: string): string {
  return label.charAt(0).toLowerCase() + label.slice(1);
}

export function capabilityLock(
  capability: WriteCapability | undefined,
  subject: string,
  permission?: string,
  roleRefusal?: string,
): string {
  if (capability === undefined || capability.allowed) return "";
  const needed =
    permission === undefined
      ? "the customer management capability"
      : `the capability to ${lowerFirst(permissionCapabilityLabel(permission))}`;
  switch (capability.blocker) {
    case "role":
      return (
        roleRefusal ??
        `${subject} is reserved for provider-level roles, and yours include neither. A role can hold the customer permissions and still not be allowed to do this.`
      );
    case "permission":
      return `${subject} needs ${needed}, which your roles do not grant.`;
    case "lifecycle":
      return `${subject} is blocked while your own customer account is not active. Restore it first.`;
    case "deployment":
      // The server means "this session belongs to another deployment". A
      // customer operator has no deployment to compare against, so the refusal
      // names the service they are actually signed in to.
      return `${subject} is blocked because this sign-in was issued for a different Nullapart service.`;
    default:
      return `${subject} is not available for your roles in this session.`;
  }
}
