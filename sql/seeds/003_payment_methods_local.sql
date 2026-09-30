-- SOLO PARA LOCAL. Este seed NO se corre contra produccion -- ahi
-- payment_methods ya tiene sus propias filas reales (con estos mismos ids,
-- confirmados por Damian contra RDS). Sin este seed, el selector de "Medio
-- de pago" del wizard de alta manual no tiene opciones en local (la tabla
-- payment_methods, creada por la migracion 077, queda vacia).
--
-- Usa los mismos ids (uuid) y nombres que produccion para que un payload de
-- prueba armado en local con un payment_method_id real siga siendo valido
-- si se compara contra produccion. ON CONFLICT (id) DO NOTHING: repetible,
-- no pisa datos si ya se corrio antes.

INSERT INTO public.payment_methods (id, nombre, organization_id, activo)
SELECT v.id, v.nombre, v.organization_id, true
FROM (
  VALUES
    ('4d76786a-2fc0-46cb-a08c-33f8fd05e7c9'::uuid, 'Anjuped', '9223d62d-f558-4f4c-b9bd-9dcea9888a0e'::uuid),
    ('e47e8601-4005-476f-a8cb-aacddc388c2d'::uuid, 'Antel', '9223d62d-f558-4f4c-b9bd-9dcea9888a0e'::uuid),
    ('08d50c77-eb5b-4757-9b84-137d6e7d3829'::uuid, 'Mastercard', '9223d62d-f558-4f4c-b9bd-9dcea9888a0e'::uuid),
    ('6c11a66c-0067-4270-a05b-328b41f0d570'::uuid, 'Mercado Pago', '9223d62d-f558-4f4c-b9bd-9dcea9888a0e'::uuid),
    ('6c9f60b2-fab4-4cb1-8d0f-a933d25e72b4'::uuid, 'OCA', '9223d62d-f558-4f4c-b9bd-9dcea9888a0e'::uuid),
    ('40644517-0df3-43bd-99e8-ac508fcabc98'::uuid, 'Visa', '9223d62d-f558-4f4c-b9bd-9dcea9888a0e'::uuid),
    ('d1592a75-a106-4f49-8c2b-9d1500c01f82'::uuid, 'AFP', 'b1ea7e1c-2c6e-48e3-ae13-e6f25d5edab8'::uuid),
    ('b58fa97c-c28d-41f5-82f6-babb09600515'::uuid, 'Ajupen Trabajadores del Ayer', 'b1ea7e1c-2c6e-48e3-ae13-e6f25d5edab8'::uuid),
    ('85339eeb-37a8-4b59-93a6-bce1c563f6d3'::uuid, 'Antel', 'b1ea7e1c-2c6e-48e3-ae13-e6f25d5edab8'::uuid),
    ('a71ee856-dfbf-4cd2-b936-cbcbf9da3c0b'::uuid, 'Mastercard', 'b1ea7e1c-2c6e-48e3-ae13-e6f25d5edab8'::uuid),
    ('82565b55-89cb-44f0-9250-e9f92e61ee55'::uuid, 'OCA', 'b1ea7e1c-2c6e-48e3-ae13-e6f25d5edab8'::uuid),
    ('a7d5b3bf-5cca-44eb-b2c6-1a4bcc8f4138'::uuid, 'Visa', 'b1ea7e1c-2c6e-48e3-ae13-e6f25d5edab8'::uuid)
) AS v(id, nombre, organization_id)
WHERE EXISTS (SELECT 1 FROM public.organizations o WHERE o.id = v.organization_id)
ON CONFLICT (id) DO NOTHING;
