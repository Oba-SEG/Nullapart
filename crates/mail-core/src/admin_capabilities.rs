//! The canonical server-resolved write capability published to the console.
//!
//! Every gate that withholds an action publishes *why* it withheld it, in this
//! one shape, so a locked control can name the enforced permission or identity
//! instead of leaving the operator to press a button that only ever returns
//! 403. `frontend/src/api/capabilities.ts` mirrors these wire values.

use serde::Serialize;

/// Which gate refused a write.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Blocker {
    /// The session's roles do not grant the route permission.
    Permission,
    /// The actor's own customer is not active.
    Lifecycle,
    /// The session was issued for another deployment.
    Deployment,
    /// The permission is held, but no built-in role that may perform this
    /// identity-level change backs it.
    Role,
}

/// One server-resolved write capability. `blocker` is `None` exactly when
/// `allowed` is true; the interactive step-up requirement is deliberately not
/// modelled here because step-up is granted per request, not per session.
#[derive(Debug, Serialize)]
pub(crate) struct WriteCapability {
    pub(crate) allowed: bool,
    pub(crate) blocker: Option<Blocker>,
}

impl WriteCapability {
    pub(crate) fn from_blocker(blocker: Option<Blocker>) -> Self {
        WriteCapability {
            allowed: blocker.is_none(),
            blocker,
        }
    }
}
