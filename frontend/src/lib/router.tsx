import {
  createRouter,
  createRootRoute,
  createRoute,
  redirect,
  lazyRouteComponent,
} from "@tanstack/react-router";
import { hasPermission, loadSession, type Session } from "../auth/session";
import { hasSeenSession } from "../api/client";
import { Layout } from "../components/Layout";

// Auth guard — redirects to /login if no valid session
async function requireAuth(): Promise<Session> {
  const session = await loadSession();
  if (!session) {
    throw redirect({
      to: "/login",
      search: { reason: hasSeenSession() ? "expired" : undefined },
    });
  }
  return session;
}

// Permission guard — UI affordance only; every API call re-authorizes.
async function requirePermission(permission: string): Promise<Session> {
  const session = await requireAuth();
  if (!hasPermission(session, permission)) {
    throw redirect({ to: "/" });
  }
  return session;
}

// Permission guard for routes whose navigation affordance is valid for more
// than one capability. API handlers still enforce the final server-side
// authorization boundary.
async function requireAnyPermission(permissions: string[]): Promise<Session> {
  const session = await requireAuth();
  if (!permissions.some((permission) => hasPermission(session, permission))) {
    throw redirect({ to: "/" });
  }
  return session;
}

// Public routes that don't require auth
async function publicOnly() {
  const session = await loadSession();
  if (session) {
    throw redirect({ to: "/" });
  }
}

// Define routes
const rootRoute = createRootRoute({
  component: Layout,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: requireAuth,
  component: lazyRouteComponent(() => import("../pages/Dashboard"), "Dashboard"),
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  beforeLoad: publicOnly,
  component: lazyRouteComponent(() => import("../pages/Login"), "Login"),
});

const messagesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/messages",
  beforeLoad: () => requirePermission("trace:view"),
  component: lazyRouteComponent(() => import("../pages/Messages"), "Messages"),
});

const messageDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/messages/$messageId",
  beforeLoad: () => requirePermission("trace:view"),
  component: lazyRouteComponent(() => import("../pages/MessageDetail"), "MessageDetail"),
});

const quarantineRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/quarantine",
  beforeLoad: () => requirePermission("quarantine:view"),
  component: lazyRouteComponent(() => import("../pages/Quarantine"), "Quarantine"),
});

const quarantineDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/quarantine/$tenant_message_id",
  beforeLoad: () => requirePermission("quarantine:view"),
  component: lazyRouteComponent(() => import("../pages/QuarantineDetail"), "QuarantineDetail"),
});

const scannerOperationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/scanner-operations",
  beforeLoad: () => requirePermission("scanner:operations:view"),
  component: lazyRouteComponent(() => import("../pages/ScannerOperations"), "ScannerOperations"),
});

const domainSecurityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/domain-security",
  beforeLoad: () => requirePermission("domain-security:view"),
  component: lazyRouteComponent(() => import("../pages/DomainSecurity"), "DomainSecurity"),
});

const outboundIntelligenceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/outbound-intelligence",
  beforeLoad: () => requirePermission("outbound-intelligence:view"),
  component: lazyRouteComponent(
    () => import("../pages/OutboundIntelligence"),
    "OutboundIntelligence",
  ),
});

const operationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/operations",
  beforeLoad: () => requirePermission("operations:view"),
  component: lazyRouteComponent(() => import("../pages/Operations"), "Operations"),
});

const auditLogRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/audit-log",
  beforeLoad: () => requirePermission("audit:view"),
  component: lazyRouteComponent(() => import("../pages/AuditLog"), "AuditLog"),
});

const adminUsersRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/admin-users",
  beforeLoad: () => requireAnyPermission(["admin:users:manage", "admin:impersonate"]),
  component: lazyRouteComponent(() => import("../pages/AdminUsers"), "AdminUsers"),
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  beforeLoad: requireAuth,
  component: lazyRouteComponent(() => import("../pages/Settings"), "Settings"),
});

const customersRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/customers",
  beforeLoad: () => requirePermission("admin:customers:view"),
  component: lazyRouteComponent(() => import("../pages/Customers"), "Customers"),
});

const customerDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/customers/$customerId",
  beforeLoad: () => requirePermission("admin:customers:view"),
  component: lazyRouteComponent(() => import("../pages/CustomerDetail"), "CustomerDetail"),
});

const policiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policies",
  beforeLoad: () => requirePermission("policies:view"),
  component: lazyRouteComponent(() => import("../pages/Policies"), "Policies"),
});

const policyFamilyDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policies/$familyKey",
  beforeLoad: () => requirePermission("policies:view"),
  component: lazyRouteComponent(() => import("../pages/PolicyFamilyDetail"), "PolicyFamilyDetail"),
});

const featureOverridesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policies/features",
  beforeLoad: () => requirePermission("policies:view"),
  component: lazyRouteComponent(() => import("../pages/FeatureOverrides"), "FeatureOverrides"),
});

const modelsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/models",
  beforeLoad: () => requirePermission("models:view"),
  component: lazyRouteComponent(() => import("../pages/Models"), "Models"),
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  loginRoute,
  messagesRoute,
  messageDetailRoute,
  quarantineRoute,
  quarantineDetailRoute,
  scannerOperationsRoute,
  domainSecurityRoute,
  outboundIntelligenceRoute,
  operationsRoute,
  auditLogRoute,
  adminUsersRoute,
  settingsRoute,
  customersRoute,
  customerDetailRoute,
  policiesRoute,
  policyFamilyDetailRoute,
  featureOverridesRoute,
  modelsRoute,
]);

export const router = createRouter({ routeTree });

// Type declarations for router
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
