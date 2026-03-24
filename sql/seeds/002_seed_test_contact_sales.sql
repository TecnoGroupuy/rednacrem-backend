WITH new_contact AS (
  INSERT INTO public.contacts (
    nombre,
    apellido,
    email,
    telefono,
    celular,
    documento,
    fecha_nacimiento,
    direccion,
    departamento,
    pais,
    status
  )
  VALUES (
    'Contacto',
    'Prueba',
    'contacto.prueba@example.com',
    '2401 0000',
    '099 000 000',
    '4.567.890-1',
    DATE '1985-06-10',
    'Av. Test 1234',
    'Montevideo',
    'Uruguay',
    'activo'
  )
  RETURNING id
),
new_product AS (
  INSERT INTO public.products (
    nombre,
    categoria,
    descripcion,
    observaciones,
    precio,
    activo
  )
  VALUES (
    'Plan Prueba',
    'General',
    'Producto de prueba',
    NULL,
    890,
    true
  )
  RETURNING id
),
new_sale AS (
  INSERT INTO public.sales (
    contact_id,
    seller_id,
    fecha,
    medio_pago,
    seller_name_snapshot,
    seller_origin
  )
  SELECT
    nc.id,
    NULL,
    DATE '2024-03-17',
    'Débito',
    'Ana López',
    'externo'
  FROM new_contact nc
  RETURNING id, contact_id
),
new_sale_item AS (
  INSERT INTO public.sale_items (
    sale_id,
    product_id,
    cantidad,
    precio_unitario
  )
  SELECT
    ns.id,
    np.id,
    1,
    890
  FROM new_sale ns
  CROSS JOIN new_product np
  RETURNING id
)
INSERT INTO public.contact_products (
  contact_id,
  sale_id,
  nombre_producto,
  plan,
  precio,
  fecha_alta,
  cuotas_pagas,
  carencia_cuotas,
  estado,
  motivo_baja,
  motivo_baja_detalle,
  fecha_baja,
  seller_user_id,
  seller_name_snapshot,
  seller_origin
)
SELECT
  ns.contact_id,
  ns.id,
  'Plan Prueba',
  'Plan Prueba',
  890,
  DATE '2024-03-17',
  1,
  3,
  'alta',
  NULL,
  NULL,
  NULL,
  NULL,
  'Ana López',
  'externo'
FROM new_sale ns;
