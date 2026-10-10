-- 029_outbound_intelligence_control_plane.sql
-- Phase 6 Control Plane permissions for outbound intelligence.

BEGIN;

INSERT INTO admin_role_permissions (role_id, permission)
SELECT role.id, permission.permission
FROM admin_roles AS role
CROSS JOIN (VALUES
    ('outbound-intelligence:view'),
    ('outbound-intelligence:manage')
) AS permission(permission)
WHERE role.role_key IN ('system_admin', 'support')
ON CONFLICT DO NOTHING;

INSERT INTO admin_role_permissions (role_id, permission)
SELECT role.id, 'outbound-intelligence:view'
FROM admin_roles AS role
WHERE role.role_key = 'customer_admin'
ON CONFLICT DO NOTHING;

COMMIT;
