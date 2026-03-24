ALTER TABLE public.lead_batch_contacts
  DROP CONSTRAINT IF EXISTS lead_batch_contacts_contact_id_fkey;

ALTER TABLE public.lead_batch_contacts
  ADD CONSTRAINT lead_batch_contacts_contact_id_fkey
  FOREIGN KEY (contact_id) REFERENCES public.datos_para_trabajar(id) ON DELETE CASCADE;

ALTER TABLE public.lead_contact_status
  DROP CONSTRAINT IF EXISTS lead_contact_status_contact_id_fkey;

ALTER TABLE public.lead_contact_status
  ADD CONSTRAINT lead_contact_status_contact_id_fkey
  FOREIGN KEY (contact_id) REFERENCES public.datos_para_trabajar(id) ON DELETE CASCADE;

ALTER TABLE public.lead_management_history
  DROP CONSTRAINT IF EXISTS lead_management_history_contact_id_fkey;

ALTER TABLE public.lead_management_history
  ADD CONSTRAINT lead_management_history_contact_id_fkey
  FOREIGN KEY (contact_id) REFERENCES public.datos_para_trabajar(id) ON DELETE CASCADE;
