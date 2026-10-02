-- Rol "backoffice" (auditoría 2026-10, PASO 1 -- solo agrega la fila de
-- catálogo, sin tocar ningún endpoint ni capacidad todavía: eso depende de
-- decisiones de negocio pendientes, ver pasos 2 y 3).
--
-- users.role_key tiene una FK real a roles(key) (confirmado contra RDS
-- producción: users_role_key_fkey, única constraint sobre esa columna, sin
-- CHECK) -- esta fila tiene que existir en roles ANTES de que cualquier
-- código pueda escribir role_key='backoffice'. Si el deploy del backend
-- sale antes que esta migración, el próximo login de un usuario del grupo
-- Cognito "backoffice" fallaría al intentar sincronizar su role_key (ver
-- ensureUserRole en userService.js) -- Damián corre esto a mano contra RDS
-- ANTES de deployar el backend de este cambio, no al revés.
--
-- priority=3, empatado con 'operaciones' a propósito: confirmado por grep
-- que ningún código (backend ni frontend) lee la columna roles.priority
-- hoy, así que el valor es puramente descriptivo. La precedencia real de
-- mapeo de grupos de Cognito a rol vive en ROLE_KEYS (src/lib/constants.js
-- del backend), que SÍ ubica a 'backoffice' entre 'operaciones' y
-- 'vendedor' -- ver el comentario ahí para la justificación completa.
--
-- ON CONFLICT (key) DO NOTHING: idempotente si ya se corrió.

INSERT INTO roles (key, label, priority, is_active)
VALUES ('backoffice', 'Backoffice', 3, true)
ON CONFLICT (key) DO NOTHING;
