CREATE INDEX IF NOT EXISTS datos_para_trabajar_org_telefono_fecha_lead_idx
  ON public.datos_para_trabajar (organization_id, telefono, fecha_lead)
  WHERE telefono IS NOT NULL AND fecha_lead IS NOT NULL;

CREATE INDEX IF NOT EXISTS datos_para_trabajar_org_celular_fecha_lead_idx
  ON public.datos_para_trabajar (organization_id, celular, fecha_lead)
  WHERE celular IS NOT NULL AND fecha_lead IS NOT NULL;
