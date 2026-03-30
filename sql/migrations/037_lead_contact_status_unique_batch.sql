DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'lead_contact_status_contact_batch_unique'
      AND conrelid = 'lead_contact_status'::regclass
  ) THEN
    ALTER TABLE lead_contact_status
    ADD CONSTRAINT lead_contact_status_contact_batch_unique
    UNIQUE (contact_id, batch_id);
  END IF;
END $$;
