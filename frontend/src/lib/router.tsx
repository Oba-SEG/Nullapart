import { createRouter, createRoot, lazyRouteComponent } from "@tanstack/react-router";

// Define routes
const rootRoute = createRoot({
  component: () => import("../components/Layout").then((m) => m.Layout),
});

const indexRoute = rootRoute.createRoute({
  path: "/",
  component: lazyRouteComponent(() => import("../pages/Dashboard")),
});

const loginRoute = rootRoute.createRoute({
  path: "/login",
  component: lazyRouteComponent(() => import("../pages/Login")),
});

const messagesRoute = rootRoute.createRoute({
  path: "/messages",
  component: lazyRouteComponent(() => import("../pages/Messages")),
});

const messageDetailRoute = rootRoute.createRoute({
  path: "/messages/$messageId",
  component: lazyRouteComponent(() => import("../pages/MessageDetail")),
});

const quarantineRoute = rootRoute.createRoute({
  path: "/quarantine",
  component: lazyRouteComponent(() => import("../pages/Quarantine")),
});

const settingsRoute = rootRoute.createRoute({
  path: "/settings",
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
