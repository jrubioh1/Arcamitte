# Referencia de la API REST de Arcamitte (v1)

Esta especificación describe los contratos de comunicación, autenticación, encabezados y formatos de datos para la integración de sistemas externos con **Arcamitte**.

---

## 1. Esquema de Autenticación y Encabezados

Los endpoints internos y de gestión de máquina (`/api/v1/...`) requieren autenticación mediante **Tokens de Máquina (API Keys)**.

### Encabezados Admitidos
Puede remitir su clave mediante cualquiera de los siguientes dos encabezados estándar:
- `X-API-Key: arca_live_...`
- `Authorization: Bearer arca_live_...`

> [!NOTE]
> Las claves de producción comienzan con el prefijo `arca_live_` y contienen 32 bytes de entropía generados por un CSPRNG.

### Control de Ámbitos (Scopes)
| Ámbito | Descripción |
| :--- | :--- |
| `documents:read` | Lectura de metadatos y estado criptográfico de documentos. |
| `documents:write` | Ingesta, subida y reactivación de documentos cifrados. |
| `tokens:manage` | Creación, revocación y auditoría de tokens de API. |

---

## 2. Límites de Tasa (Throttling)

Para salvaguardar la disponibilidad del servicio contra ataques de denegación de servicio (DoS) y fuerza bruta contra códigos OTP:
- **Endpoints Públicos de Solicitud:** Máximo 15 solicitudes por minuto por IP.
- **Endpoints Públicos de Canje:** Máximo 30 intentos por minuto por IP.
- Si se excede el límite, el microservicio responde con código HTTP `429 Too Many Requests`.

---

## 3. Endpoints de la API v1

### 3.1 Subir y Cifrar Documento
Permite a un sistema autorizado ingerir un archivo confidencial para su custodia y entrega cifrada.

- **Método:** `POST`
- **Ruta:** `/api/v1/documents/`
- **Ámbito Requerido:** `documents:write` (o `documents:create`)
- **Content-Type:** `multipart/form-data`

> [!TIP]
> **Diseño Desacoplado:** La aplicación integradora externa **NO necesita especificar Unidades Organizativas (UO)**. Solo requiere enviar el archivo y los correos autorizados. La asignación de UO es una característica organizativa interna y 100% opcional dentro de Arcamitte.

#### Parámetros del Formulario
| Parámetro | Tipo | Requerido | Descripción |
| :--- | :--- | :--- | :--- |
| `original_file` | Binario | **Sí** | Archivo en formato permitido (PDF, DOCX, ODT, XLSX, JPG, PNG). Máx. 50 MB. |
| `allowed_emails` | Cadena / JSON | **Sí** | Correo o lista de correos autorizados para el canje con OTP (ej. `["destinatario@empresa.com"]` o `correo@empresa.com`). |
| `description` | Cadena | No | Resumen u objeto informativo del trámite confidencial. |
| `burn_policy` | Cadena | No | Política de destrucción: `FIRST_ACCESS` (por defecto) o `ALL_RECIPIENTS`. |
| `expires_at` | ISO-8601 | No | Fecha/hora límite de disponibilidad. Por defecto: +14 días. |
| `origin_uo` | Cadena / Int | No (Opcional) | Alias o código de la UO interna emisora si se desea etiquetar en la malla de Arcamitte. |
| `target_uo` | Cadena / Int | No (Opcional) | Alias o código de la UO interna receptora (opcional). |
| `reopen_existing` | Booleano | No | Si es `true` y el hash ya existe y fue consumido, reactiva la custodia con nuevos destinatarios. |

#### Ejemplo de Petición cURL (Mínimo y Desacoplado)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/documents/ \
  -H "X-API-Key: arca_live_SU_TOKEN_AQUI" \
  -F "original_file=@expediente_auditoria.pdf" \
  -F "allowed_emails=destinatario@empresa.com"
```

#### Respuesta Exitosa (201 Created)
```json
{
  "id": "e5b8d28a-7cb2-4a0b-9df6-2be5188f6194",
  "file_hash": "c5f590b2b80041d8e1f5f3e9c68c34fba3f5e5529f7cf7c65d63f47e09961dbf",
  "original_filename": "expediente_auditoria.pdf",
  "description": "Auditoría de Cumplimiento Q3",
  "origin_uo": 1001,
  "target_uo": 1002,
  "is_consumed": false,
  "burn_policy": "FIRST_DOWNLOAD",
  "authorized_emails": [
    "director@empresa.com",
    "auditor@empresa.com"
  ],
  "expires_at": "2026-11-07T12:00:00Z",
  "created_at": "2026-10-24T12:00:00Z"
}
```

---

### 3.2 Consultar Estado Criptográfico de un Documento
Permite a los sistemas clientes verificar si un documento sigue en custodia o ha sido consumido/destruido, sin exponer su contenido.

- **Método:** `GET`
- **Ruta:** `/api/v1/documents/{file_hash}/status/`
- **Ámbito Requerido:** `documents:read`

#### Ejemplo de Petición
```bash
curl -X GET http://127.0.0.1:8000/api/v1/documents/c5f590b2b80041d8e1f5f3e9c68c34fba3f5e5529f7cf7c65d63f47e09961dbf/status/ \
  -H "X-API-Key: arca_live_9d8f3a8b4c2e1f0e9d8c7b6a5f4e3d2c1b0a"
```

#### Respuesta Exitosa (200 OK)
```json
{
  "file_hash": "c5f590b2b80041d8e1f5f3e9c68c34fba3f5e5529f7cf7c65d63f47e09961dbf",
  "original_filename": "expediente_auditoria.pdf",
  "is_consumed": false,
  "is_expired": false,
  "burn_policy": "FIRST_DOWNLOAD",
  "recipients_count": 2,
  "consumed_by_count": 0,
  "created_at": "2026-10-24T12:00:00Z",
  "expires_at": "2026-11-07T12:00:00Z"
}
```

---

## 4. Endpoints Públicos de Canje (Integración de Portales)

Para portales de autoservicio o clientes ligeros que no posean sesión interactiva:

### 4.1 Solicitar Código OTP
Despacha un código de verificación al buzón del destinatario.

- **Método:** `POST`
- **Ruta:** `/arcamitte/api/public/request-access/`
- **Content-Type:** `application/json`

#### Cuerpo de la Petición
```json
{
  "file_hash": "c5f590b2b80041d8e1f5f3e9c68c34fba3f5e5529f7cf7c65d63f47e09961dbf",
  "email": "director@empresa.com"
}
```

#### Respuesta (200 OK)
```json
{
  "status": "success",
  "message": "Si los datos indicados corresponden a un documento disponible y una dirección de correo autorizada, recibirá en breve un código de verificación en su buzón."
}
```

---

### 4.2 Canjear OTP y Descargar Archivo Descifrado
Valida el código temporal e inicia el stream directo del binario descifrado en memoria.

- **Método:** `POST`
- **Ruta:** `/arcamitte/api/public/consume/`
- **Content-Type:** `application/json`

#### Cuerpo de la Petición
```json
{
  "file_hash": "c5f590b2b80041d8e1f5f3e9c68c34fba3f5e5529f7cf7c65d63f47e09961dbf",
  "email": "director@empresa.com",
  "otp_code": "489201"
}
```

#### Respuesta Exitosa (200 OK)
- **Headers:**
  - `Content-Type: application/octet-stream` (o MIME type original)
  - `Content-Disposition: attachment; filename="expediente_auditoria.pdf"`
- **Body:** Flujo de bytes binarios descifrados en memoria.
- **Efecto Inmediato:** El archivo físico en el servidor es sobrescrito con bytes aleatorios (`os.urandom`) y eliminado del almacenamiento físico.

#### Respuesta de Error (400 Bad Request)
```json
{
  "status": "error",
  "message": "El código de verificación no es válido o ha expirado."
}
```
