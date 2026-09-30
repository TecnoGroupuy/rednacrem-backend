-- Quien CARGA una venta no es necesariamente quien la vendio (ej. un
-- supervisor carga una venta de un vendedor externo). registrada_por_user_id
-- guarda siempre el usuario logueado que hizo el alta, en los 3 modos de
-- vendedor (logueado/asignado/externo) -- ver resolveSaleSeller en index.mjs.
--
-- Solo en sales. contact_products ya apunta a la venta via sale_id, no hace
-- falta duplicar la columna ahi.
--
-- APLICADA EN PRODUCCION por Damian (COMMIT confirmado) -- a diferencia de
-- 074/075/077/078 (alineacion local, no-op en prod), esta SI era un cambio
-- real: registrada_por_user_id no existia en produccion, y sin ella las
-- ventas fallan en cuanto se despliega el backend nuevo.

ALTER TABLE public.sales
  ADD COLUMN IF NOT EXISTS registrada_por_user_id uuid;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sales_registrada_por_user_id_fkey') THEN
    ALTER TABLE public.sales
      ADD CONSTRAINT sales_registrada_por_user_id_fkey
      FOREIGN KEY (registrada_por_user_id) REFERENCES public.users(id);
  END IF;
END $$;
