-- Roster persistente de vendedores por lote de Recupero — mismo patrón que
-- lead_batch_sellers en Lotes de captación. Sin esto, "Agregar vendedor" a
-- un lote sin datos libres (ej. "Prioritario — 0 a 3 meses" con 0
-- contactos) no dejaba rastro en ningún lado: "Vendedores asignados" se
-- arma agrupando seller_id sobre recupero_candidatos, así que un vendedor
-- sin ningún candidato desaparecía al recargar la página.
--
-- Sin organization_id propio a propósito (igual que lead_batch_sellers) —
-- dataset_id ya resuelve la organización vía recupero_import_jobs, y todo
-- el código que la toca ya confirma esa pertenencia antes de escribir acá.
CREATE TABLE IF NOT EXISTS public.recupero_dataset_sellers (
  id BIGSERIAL PRIMARY KEY,
  dataset_id UUID NOT NULL REFERENCES public.recupero_import_jobs(id) ON DELETE CASCADE,
  seller_id UUID NOT NULL REFERENCES public.users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (dataset_id, seller_id)
);

CREATE INDEX IF NOT EXISTS recupero_dataset_sellers_dataset_idx ON public.recupero_dataset_sellers (dataset_id);
CREATE INDEX IF NOT EXISTS recupero_dataset_sellers_seller_idx ON public.recupero_dataset_sellers (seller_id);
