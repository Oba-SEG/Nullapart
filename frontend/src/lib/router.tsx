import {
  createRouter,
  createRootRoute,
  createRoute,
  redirect,
  lazyRouteComponent,
} from "@tanstack/react-router";
import { loadSession } from "../auth/session";

// Auth guard — redirects to /login if no valid session
async function requireAuth() {
  const session = await loadSession();
  if (!session) {
    throw redirect({ to: "/login" });
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
  component: () => import("../components/Layout").then((m) => m.Layout),
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: requireAuth,
  component: lazyRouteComponent(() => import("../pages/Dashboard")),
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  beforeLoad: publicOnly,
  component: lazyRouteComponent(() => import("../pages/Login")),
});

const messagesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/messages",
  beforeLoad: requireAuth,
  component: lazyRouteComponent(() => import("../pages/Messages")),
});

const messageDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/messages/$messageId",
  beforeLoad: requireAuth,
  component: lazyRouteComponent(() => import("../pages/MessageDetail")),
});

const quarantineRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/quarantine",
  beforeLoad: requireAuth,
  component: lazyRouteComponent(() => import("../pages/Quarantine")),
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  beforeLoad: requireAuth,
  component: lazyRouteComponent(() => import("../pages/Settings")),
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  loginRoute,
  messagesRoute,
  messageDetailRoute,
  quarantineRoute,
  settingsRoute,
]);

export const router = createRouter({ routeTree });

// Type declarations for router
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
