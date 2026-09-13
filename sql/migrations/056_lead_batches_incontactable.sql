ALTER TABLE public.lead_contact_status
  DROP CONSTRAINT IF EXISTS lead_contact_status_estado_check;

ALTER TABLE public.lead_contact_status
  ADD CONSTRAINT lead_contact_status_estado_check
  CHECK (
    estado_venta IN (
      'nuevo',
      'no_contesta',
      'seguimiento',
      'rellamar',
      'rechazo',
      'dato_erroneo',
      'venta',
      'incontactable'
    )
  );

INSERT INTO public.lead_status_catalog (nombre, es_final, libera_al_cerrar)
VALUES ('incontactable', true, true)
ON CONFLICT (nombre) DO NOTHING;

ALTER TABLE public.lead_batches
  ADD COLUMN IF NOT EXISTS incontactable_enabled boolean NOT NULL DEFAULT false;
