-- Link de autocompletado de ficha publica (RRHH SU Emergencia): rate-limit
-- por documento ademas del ya existente por IP, y tabla de auditoria de
-- cambios hechos por el propio funcionario via el link publico.
--
-- Damian corre este archivo contra RDS; el agente no la ejecuta contra
-- produccion. Idempotente: ALTER ... ADD COLUMN IF NOT EXISTS y
-- CREATE TABLE/INDEX IF NOT EXISTS en todos los pasos.

-- ficha_publica_intentos ya existe (migracion 060), solo IP hasta ahora.
-- documento es NULL para las filas viejas (no se reconstruye el dato
-- retroactivamente) -- el codigo trata una fila sin documento como "no
-- cuenta para el limite por documento", el limite por IP sigue intacto.
ALTER TABLE public.ficha_publica_intentos
  ADD COLUMN IF NOT EXISTS documento text NULL;

CREATE INDEX IF NOT EXISTS ficha_publica_intentos_documento_created_idx
  ON public.ficha_publica_intentos (documento, created_at)
  WHERE documento IS NOT NULL;

-- Una fila por cada campo que el funcionario cambia desde el link publico
-- (telefono/email/domicilio/fecha_nacimiento), y tambien por cada cambio de
-- foto -- nunca por cambios hechos desde la ficha interna autenticada (esos
-- ya tienen su propio rastro de auditoria implicito via updated_at + quien
-- esta logueado). Es un log de auditoria append-only: sin updated_at ni
-- trigger de set_updated_at (no se edita ninguna fila despues de insertada).
CREATE TABLE IF NOT EXISTS public.su_personal_cambios_publicos (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id),
  personal_id uuid NOT NULL REFERENCES public.su_personal(id) ON DELETE CASCADE,
  campo text NOT NULL,
  valor_anterior text NULL,
  valor_nuevo text NULL,
  ip text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS su_personal_cambios_publicos_personal_id_idx
  ON public.su_personal_cambios_publicos (personal_id, created_at DESC);

CREATE INDEX IF NOT EXISTS su_personal_cambios_publicos_organization_id_idx
  ON public.su_personal_cambios_publicos (organization_id);
