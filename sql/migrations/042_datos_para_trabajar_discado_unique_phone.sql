DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'datos_para_trabajar'
      AND column_name IN ('organization_id', 'telefono', 'origen_dato')
    GROUP BY table_schema, table_name
    HAVING COUNT(*) = 3
  ) THEN
    -- Unique only for Discado auto rows, to support upsert-by-phone without breaking existing data.
    EXECUTE $sql$
      CREATE UNIQUE INDEX IF NOT EXISTS datos_para_trabajar_discado_org_telefono_uidx
      ON public.datos_para_trabajar (organization_id, telefono)
      WHERE origen_dato = 'Discado auto'
        AND telefono IS NOT NULL
        AND btrim(telefono) <> ''
    $sql$;
  END IF;
END $$;

