import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

const DEFAULT_LOGO_PATH = "Logo_certificado_rednacrem.png";
const DEFAULT_STAMP_PATH = "Firma_certificado.png";

const PAGE_WIDTH = 595.28;
const PAGE_HEIGHT = 841.89;

function escapePdfText(text) {
  return String(text || "")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

function formatDateEs(date) {
  if (!date) return "";
  const d = date instanceof Date ? date : new Date(date);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleDateString("es-UY");
}

export function buildClientDocumentFilename(client) {
  const rawName = [client?.nombre, client?.apellido].filter(Boolean).join(" ").trim() || "Cliente";
  const name = rawName
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  const documento = String(client?.documento || "Documento")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `Certificado_Cremacion_${name}_${documento}.pdf`;
}

function estimateTextWidth(text, fontSize) {
  return String(text || "").length * fontSize * 0.5;
}

function wrapText(text, maxWidth, fontSize) {
  const words = String(text || "").split(/\s+/).filter(Boolean);
  const lines = [];
  let current = "";

  for (const word of words) {
    const tentative = current ? `${current} ${word}` : word;
    if (estimateTextWidth(tentative, fontSize) <= maxWidth) {
      current = tentative;
    } else {
      if (current) lines.push(current);
      current = word;
    }
  }

  if (current) lines.push(current);
  return lines;
}

function parsePng(buffer) {
  const signature = buffer.slice(0, 8);
  const expected = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (!signature.equals(expected)) {
    throw new Error("Invalid PNG signature");
  }

  let offset = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 8;
  let colorType = 6;
  const idatChunks = [];

  while (offset < buffer.length) {
    const length = buffer.readUInt32BE(offset);
    offset += 4;
    const type = buffer.slice(offset, offset + 4).toString("ascii");
    offset += 4;
    const data = buffer.slice(offset, offset + length);
    offset += length;
    offset += 4; // CRC

    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data.readUInt8(8);
      colorType = data.readUInt8(9);
    } else if (type === "IDAT") {
      idatChunks.push(data);
    } else if (type === "IEND") {
      break;
    }
  }

  return {
    width,
    height,
    bitDepth,
    colorType,
    data: Buffer.concat(idatChunks)
  };
}

function decodePngRgba(png) {
  if (png.bitDepth !== 8) {
    throw new Error("Unsupported PNG bit depth");
  }
  if (png.colorType !== 6) {
    throw new Error("Unsupported PNG color type");
  }

  const bytesPerPixel = 4;
  const stride = png.width * bytesPerPixel;
  const inflated = zlib.inflateSync(png.data);
  const output = Buffer.alloc(png.width * png.height * bytesPerPixel);

  let inOffset = 0;
  let outOffset = 0;
  const prevLine = Buffer.alloc(stride);

  for (let y = 0; y < png.height; y += 1) {
    const filterType = inflated[inOffset];
    inOffset += 1;
    const line = inflated.slice(inOffset, inOffset + stride);
    inOffset += stride;

    const recon = Buffer.alloc(stride);

    for (let x = 0; x < stride; x += 1) {
      const left = x >= bytesPerPixel ? recon[x - bytesPerPixel] : 0;
      const up = prevLine[x];
      const upLeft = x >= bytesPerPixel ? prevLine[x - bytesPerPixel] : 0;
      let value = line[x];

      switch (filterType) {
        case 0:
          break;
        case 1:
          value = (value + left) & 0xff;
          break;
        case 2:
          value = (value + up) & 0xff;
          break;
        case 3:
          value = (value + Math.floor((left + up) / 2)) & 0xff;
          break;
        case 4: {
          const p = left + up - upLeft;
          const pa = Math.abs(p - left);
          const pb = Math.abs(p - up);
          const pc = Math.abs(p - upLeft);
          let pr = left;
          if (pb <= pa && pb <= pc) pr = up;
          if (pc <= pa && pc <= pb) pr = upLeft;
          value = (value + pr) & 0xff;
          break;
        }
        default:
          throw new Error("Unsupported PNG filter");
      }

      recon[x] = value;
    }

    recon.copy(output, outOffset);
    recon.copy(prevLine, 0);
    outOffset += stride;
  }

  return {
    width: png.width,
    height: png.height,
    data: output
  };
}

function buildPdfImageObjects(image, objects) {
  if (!image) return null;

  const { width, height, data } = image;
  const rgb = Buffer.alloc(width * height * 3);
  const alpha = Buffer.alloc(width * height);

  for (let i = 0, j = 0, k = 0; i < data.length; i += 4, j += 3, k += 1) {
    rgb[j] = data[i];
    rgb[j + 1] = data[i + 1];
    rgb[j + 2] = data[i + 2];
    alpha[k] = data[i + 3];
  }

  const rgbCompressed = zlib.deflateSync(rgb);
  const alphaCompressed = zlib.deflateSync(alpha);

  const maskObjNum = addPdfObject(
    objects,
    buildStreamObject(
      `<< /Type /XObject /Subtype /Image /Width ${width} /Height ${height} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length ${alphaCompressed.length} >>`,
      alphaCompressed
    )
  );

  const imageObjNum = addPdfObject(
    objects,
    buildStreamObject(
      `<< /Type /XObject /Subtype /Image /Width ${width} /Height ${height} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /SMask ${maskObjNum} 0 R /Length ${rgbCompressed.length} >>`,
      rgbCompressed
    )
  );

  return { imageObjectNumber: imageObjNum, maskObjectNumber: maskObjNum };
}

function buildStreamObject(dict, data) {
  return Buffer.concat([
    Buffer.from(`${dict}\nstream\n`),
    data,
    Buffer.from("\nendstream")
  ]);
}

function addPdfObject(objects, content) {
  objects.push(Buffer.isBuffer(content) ? content : Buffer.from(String(content)));
  return objects.length;
}

function buildPdf(objects, rootObjectNumber) {
  const parts = [];
  const offsets = [0];
  let length = 0;

  const push = (buf) => {
    parts.push(buf);
    length += buf.length;
  };

  push(Buffer.from("%PDF-1.4\n"));

  objects.forEach((obj, index) => {
    offsets[index + 1] = length;
    push(Buffer.from(`${index + 1} 0 obj\n`));
    push(Buffer.isBuffer(obj) ? obj : Buffer.from(String(obj)));
    push(Buffer.from("\nendobj\n"));
  });

  const xrefStart = length;
  const size = objects.length + 1;
  let xref = `xref\n0 ${size}\n0000000000 65535 f \n`;
  for (let i = 1; i < size; i += 1) {
    xref += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  }
  push(Buffer.from(xref));

  const trailer = `trailer\n<< /Size ${size} /Root ${rootObjectNumber} 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;
  push(Buffer.from(trailer));

  return Buffer.concat(parts);
}

function paymentMethodLabel(value) {
  const normalized = String(value || "").toLowerCase();
  switch (normalized) {
    case "debito":
      return "Débito";
    case "credito":
      return "Crédito";
    case "efectivo":
      return "Efectivo";
    case "transferencia":
      return "Transferencia";
    default:
      return normalized ? normalized[0].toUpperCase() + normalized.slice(1) : "—";
  }
}

function computeCarenciaMonthsByBirthdate(birthdate) {
  if (!birthdate) return 0;
  const d = birthdate instanceof Date ? birthdate : new Date(birthdate);
  if (Number.isNaN(d.getTime())) return 0;
  const now = new Date();
  let age = now.getFullYear() - d.getFullYear();
  const m = now.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < d.getDate())) {
    age -= 1;
  }
  if (age < 80) return 12;
  return 24;
}

export function generateCertificatePdf(payload) {
  const client = payload?.client || {};
  const sale = payload?.sale || {};
  const product = payload?.product || {};

  const saleDate = sale.fecha || product.fecha_alta || client.created_at || new Date();
  const saleDateLabel = formatDateEs(saleDate);
  const birthdate = client.fecha_nacimiento || client.fechaNacimiento;
  const carenciaMeses = computeCarenciaMonthsByBirthdate(birthdate);
  const medioPago = paymentMethodLabel(sale.medio_pago || sale.medioPago);
  const productPrice = product.precio || sale.precio_unitario || 0;

  const logoPath = process.env.CERTIFICATE_LOGO_PATH || DEFAULT_LOGO_PATH;
  const stampPath = process.env.CERTIFICATE_STAMP_PATH || DEFAULT_STAMP_PATH;

  let logoImage = null;
  let stampImage = null;

  try {
    const resolvedLogo = fs.existsSync(logoPath)
      ? logoPath
      : path.join(process.cwd(), logoPath);
    if (fs.existsSync(resolvedLogo)) {
      const png = parsePng(fs.readFileSync(resolvedLogo));
      logoImage = decodePngRgba(png);
    }
  } catch {
    logoImage = null;
  }

  try {
    const resolvedStamp = fs.existsSync(stampPath)
      ? stampPath
      : path.join(process.cwd(), stampPath);
    if (fs.existsSync(resolvedStamp)) {
      const png = parsePng(fs.readFileSync(resolvedStamp));
      stampImage = decodePngRgba(png);
    }
  } catch {
    stampImage = null;
  }

  const objects = [];
  const fontRegular = addPdfObject(objects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const fontBold = addPdfObject(objects, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");

  let logoRef = null;
  let stampRef = null;
  if (logoImage) {
    logoRef = buildPdfImageObjects(logoImage, objects);
  }
  if (stampImage) {
    stampRef = buildPdfImageObjects(stampImage, objects);
  }

  const contentLines = [];
  const margin = 60;
  let cursorY = PAGE_HEIGHT - margin;

  contentLines.push("0 0 0 rg");
  contentLines.push("0 0 0 RG");

  if (logoRef) {
    const logoWidth = 140;
    const logoHeight = Math.round((logoImage.height / logoImage.width) * logoWidth);
    const logoX = (PAGE_WIDTH - logoWidth) / 2;
    const logoY = cursorY - logoHeight;
    contentLines.push(`q ${logoWidth} 0 0 ${logoHeight} ${logoX.toFixed(2)} ${logoY.toFixed(2)} cm /ImLogo Do Q`);
    cursorY = logoY - 18;
  }

  const title = "CERTIFICADO DE COBERTURA - CREMACION FUNERARIA";
  const titleFontSize = 11;
  const titleWidth = estimateTextWidth(title, titleFontSize);
  contentLines.push(`BT /F2 ${titleFontSize} Tf ${((PAGE_WIDTH - titleWidth) / 2).toFixed(2)} ${cursorY.toFixed(2)} Td (${escapePdfText(title)}) Tj ET`);
  cursorY -= 22;

  const cityDate = `Montevideo, ${saleDateLabel}.`;
  const dateFontSize = 10;
  const dateWidth = estimateTextWidth(cityDate, dateFontSize);
  contentLines.push(`BT /F1 ${dateFontSize} Tf ${(PAGE_WIDTH - margin - dateWidth).toFixed(2)} ${cursorY.toFixed(2)} Td (${escapePdfText(cityDate)}) Tj ET`);
  cursorY -= 20;

  const lineHeight = 12;
  const bodyFontSize = 10;
  const maxWidth = PAGE_WIDTH - margin * 2;

  const body1 = [
    "A quien corresponda:",
    `Por medio de la presente se deja constancia que ${[client.nombre, client.apellido].filter(Boolean).join(" ")} poseedor del documento de identidad ${client.documento || "-"} con la cobertura de la Red Nacional de Crematorios vigente al dia de la fecha, tras corroborar por su afiliacion no existe atrasos en los pagos mensualidad. La contratacion de la cobertura se produjo ${saleDateLabel} con un plazo de carencia de ${carenciaMeses} meses para la adquisicion de derechos. Una vez transcurrido este periodo de tiempo, el cliente contara con los derechos de cobertura transferibles del servicio de cremacion funeraria de restos de la Red Nacional de Crematorios. La misma incluye traslado de restos, urna cineraria, servicios notariales y sala de cremacion privada, a coordinarse por RED.NA.CREM dentro de los limites del territorio nacional, siempre y cuando el titular del servicio se encuentre al dia con las cuotas de la afiliacion.`
  ];

  for (const paragraph of body1) {
    const lines = wrapText(paragraph, maxWidth, bodyFontSize);
    for (const line of lines) {
      contentLines.push(`BT /F1 ${bodyFontSize} Tf ${margin.toFixed(2)} ${cursorY.toFixed(2)} Td (${escapePdfText(line)}) Tj ET`);
      cursorY -= lineHeight;
    }
    cursorY -= 6;
  }

  const noteTitle = "Nota Importante:";
  contentLines.push(`BT /F2 ${bodyFontSize} Tf ${margin.toFixed(2)} ${cursorY.toFixed(2)} Td (${escapePdfText(noteTitle)}) Tj ET`);
  const noteText = `Recuerde que el servicio a partir de la contratacion estara presente en su factura de ${medioPago} con un valor de $ ${Number(productPrice || 0).toLocaleString("es-UY")} mensuales con el detalle "ISMO.ASOCIACION DE CREMATORIOS".`;
  const noteLines = wrapText(noteText, maxWidth - estimateTextWidth(noteTitle, bodyFontSize) - 6, bodyFontSize);
  let noteX = margin + estimateTextWidth(noteTitle, bodyFontSize) + 6;
  let first = true;
  for (const line of noteLines) {
    const x = first ? noteX : margin;
    contentLines.push(`BT /F1 ${bodyFontSize} Tf ${x.toFixed(2)} ${cursorY.toFixed(2)} Td (${escapePdfText(line)}) Tj ET`);
    cursorY -= lineHeight;
    first = false;
  }
  cursorY -= 6;

  const medioPagoLabel = medioPago || "medio de pago";
  const noteText2 = `${medioPagoLabel} es un medio de cobranza descentralizado y no tiene relacion alguna con el servicio contratado, no gestiona, no coordina, ni opera para dar servicios crematorios a traves de la Red Nacional de Crematorios.`;
  const noteLines2 = wrapText(noteText2, maxWidth, bodyFontSize);
  for (const line of noteLines2) {
    contentLines.push(`BT /F1 ${bodyFontSize} Tf ${margin.toFixed(2)} ${cursorY.toFixed(2)} Td (${escapePdfText(line)}) Tj ET`);
    cursorY -= lineHeight;
  }
  cursorY -= 10;

  const contactLine = "Por gestiones comerciales o solicitudes de asistencia debe comunicarse al 08001106";
  const contactLines = wrapText(contactLine, maxWidth, bodyFontSize);
  for (const line of contactLines) {
    contentLines.push(`BT /F1 ${bodyFontSize} Tf ${margin.toFixed(2)} ${cursorY.toFixed(2)} Td (${escapePdfText(line)}) Tj ET`);
    cursorY -= lineHeight;
  }

  // Signature block (image above text) positioned after the contact line.
  cursorY -= 50;
  const signatureLineHeight = 14;
  const signatureLines = [
    "Por RED.NA.CREM",
    "M.Rodriguez",
    "Atencion al afiliado",
    "www.renacrem.com"
  ];

  let stampWidth = 90;
  let stampHeight = stampImage
    ? Math.round((stampImage.height / stampImage.width) * stampWidth)
    : 0;
  let stampX = margin + 6;
  let stampY = cursorY - stampHeight;
  let textStartY = stampY - 15;
  const minTextY = 80;
  if (textStartY < minTextY) {
    const delta = minTextY - textStartY;
    textStartY += delta;
    stampY += delta;
  }

  if (stampRef) {
    contentLines.push(`q ${stampWidth} 0 0 ${stampHeight} ${stampX.toFixed(2)} ${stampY.toFixed(2)} cm /ImStamp Do Q`);
  }

  let currentSigY = textStartY;
  signatureLines.forEach((line, index) => {
    const font = index === 0 ? "F2" : "F1";
    contentLines.push(`BT /${font} ${bodyFontSize} Tf ${margin.toFixed(2)} ${currentSigY.toFixed(2)} Td (${escapePdfText(line)}) Tj ET`);
    currentSigY -= signatureLineHeight;
  });

  const footerLine1 = "Red Nacional de Crematorios - Torre de los Profesionales of. 702 - Montevideo Uruguay";
  const footerLine2 = "Tel: 0800 1106 - Mail: contacto@rednacrem.com";
  contentLines.push(`BT /F1 8 Tf ${((PAGE_WIDTH - estimateTextWidth(footerLine1, 8)) / 2).toFixed(2)} 34 Td (${escapePdfText(footerLine1)}) Tj ET`);
  contentLines.push(`BT /F1 8 Tf ${((PAGE_WIDTH - estimateTextWidth(footerLine2, 8)) / 2).toFixed(2)} 22 Td (${escapePdfText(footerLine2)}) Tj ET`);

  const contentStream = contentLines.join("\n");
  const contentObj = addPdfObject(
    objects,
    buildStreamObject(
      `<< /Length ${Buffer.byteLength(contentStream)} >>`,
      Buffer.from(contentStream)
    )
  );

  const pageObjNum = objects.length + 1;
  const pagesObjNum = objects.length + 2;
  const catalogObjNum = objects.length + 3;

  const xObjectEntries = [];
  if (logoRef) xObjectEntries.push(`/ImLogo ${logoRef.imageObjectNumber} 0 R`);
  if (stampRef) xObjectEntries.push(`/ImStamp ${stampRef.imageObjectNumber} 0 R`);
  const xObjectSection = xObjectEntries.length
    ? `/XObject << ${xObjectEntries.join(" ")} >>`
    : "";

  addPdfObject(
    objects,
    `<< /Type /Page /Parent ${pagesObjNum} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 ${fontRegular} 0 R /F2 ${fontBold} 0 R >> ${xObjectSection} >> /Contents ${contentObj} 0 R >>`
  );
  addPdfObject(objects, `<< /Type /Pages /Kids [${pageObjNum} 0 R] /Count 1 >>`);
  addPdfObject(objects, `<< /Type /Catalog /Pages ${pagesObjNum} 0 R >>`);

  return buildPdf(objects, catalogObjNum);
}
