ALTER TABLE public.datos_para_trabajar
  ADD COLUMN IF NOT EXISTS campaign_name varchar(255),
  ADD COLUMN IF NOT EXISTS form_name varchar(255);
