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

/** Which gate refused the write. Mirrors `Blocker` in mail-core. */
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
 */
export function capabilityLock(capability: WriteCapability | undefined, subject: string): string {
  if (capability === undefined || capability.allowed) return "";
  switch (capability.blocker) {
    case "role":
      return `${subject} is limited to the Support and System roles, and yours include neither. A role can hold the customer permissions and still not be allowed to do this.`;
    case "permission":
      return `${subject} needs the customer management permission, which your roles do not grant.`;
    case "lifecycle":
      return `${subject} is blocked while your own customer account is not active. Restore it first.`;
    case "deployment":
      return `${subject} is blocked because this session was issued for a different deployment.`;
    default:
      return `${subject} is not available for your roles in this session.`;
  }
}
