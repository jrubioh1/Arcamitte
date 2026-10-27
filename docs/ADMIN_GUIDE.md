# Manual de Operaciones y Administración de Arcamitte

Esta guía está dirigida a Oficiales de Seguridad de la Información (CISO), Administradores de Sistemas y Operadores departamentales responsables del despliegue y mantenimiento de **Arcamitte**.

---

## 1. Acceso y Panel de Control

Arcamitte centraliza toda su gobernanza a través de su portal bespoke:

### 1.1 Cyber-Ops Bespoke Dashboard (`/dashboard/`)
Panel de control visual moderno desarrollado con **Tailwind CSS + Flowbite** y arquitectura de componentes propia de Arcamitte, optimizado para operaciones de alta seguridad (ENS ALTO / Zero Trust):
- **Resumen Ejecutivo (KPIs):** Conteo de documentos bajo custodia activa, archivos consumidos y sanitizados, UOs registradas y volumen de eventos.
- **Gestor Documental:** Listado paginado con filtros por UO y estado, buscador en tiempo real por nombre de archivo o hash SHA-256.
- **Subida Segura:** Asistente de custodia con cálculo de hash en cliente, selección de UO emisora/receptora y política de destrucción.
- **Detalle y Auditoría:** Inspección de metadatos, línea temporal de eventos y finalización anticipada por vicisitud.
- **Gestión de UOs y Miembros:** Alta y edición de unidades organizativas y asignación de usuarios con roles de Operador, Auditor o Administrador de UO.
- **Directorio de Usuarios:** Creación y modificación de cuentas con contraseñas temporales automáticas de alta entropía.
- **Carga Masiva (JSON):** Aprovisionamiento simultáneo e idempotente de UOs y usuarios desde el propio Dashboard.
- **Gobernanza 2FA y Perímetro:** Despliegue de segundo factor TOTP (RFC 6238), reseteo de claves y baneo preventivo de IPs sospechosas.
- **Pasarela de Tokens API:** Generación de credenciales M2M con scopes específicos y revocación inmediata.

### 1.2 Matriz de Roles y Atribuciones

| Rol | Cifrar y Tramitar | Consultar Asientos | Descarga de Auditoría Forense Preservada | Terminar y Destruir Asiento | Gestión de Personal UO | Gobernanza Global |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Operador** | ✅ Sí | ✅ Sí (de su UO) | ❌ No | ❌ No | ❌ No | ❌ No |
| **Auditor** | ✅ Sí | ✅ Sí (de su UO) | ✅ **Sí (Exclusivo UO)** | ❌ No | ❌ No | ❌ No |
| **Admin de UO** | ✅ Sí | ✅ Sí (de su UO) | ✅ Sí (de su UO) | ✅ **Sí (Solo de su UO)** | ✅ Sí | ❌ No |
| **Superusuario / Admin Global** | ✅ Sí | ✅ Sí (Global) | ✅ Sí (Global) | ✅ **Sí (Cualquier asiento)** | ✅ Sí | ✅ Sí |

#### Claves Operativas de los Roles:
- **Operador (`Role.OPERATOR`):** Cifra y envía trámites. No tiene acceso a descargas periciales ni a la destrucción manual anticipada de asientos.
- **Auditor (`Role.AUDITOR`):** Puede realizar **Descargas de Auditoría Forense Preservadas** para peritajes o requerimientos legales sin consumir el asiento ni alterar el archivo en disco (evento `ADMIN_DESCARGA_PRESERVADA`).
- **Administrador de UO (`Role.ADMIN`):** Administra el personal de su UO (altas, roles, reseteo de claves) y puede destruir/finalizar anticipadamente asientos de su UO.
- **Superusuario / Administrador Global (`is_global_admin`):** Soberanía completa sin restricciones de departamento, gestión de claves maestras, perímetro de IPs y tokens M2M. Puede estar adscrito directamente a una UO con rol departamental o actuar de forma transversal.

---

## 2. Aprovisionamiento Masivo mediante JSON

Para dar de alta estructuras organizativas complejas de forma rápida e idempotente, Arcamitte incluye un motor de importación por lotes ejecutable tanto desde el Dashboard como por CLI.

### 2.1 Formato del Archivo JSON
Cree un archivo con la estructura:
```json
{
  "organizational_units": [
    {
      "numeric_code": 1001,
      "alias": "SEC-OPS",
      "name": "Dirección de Ciberseguridad",
      "email": "secops@seguridad.local",
      "description": "SOC, gobernanza y gestión de incidentes",
      "is_active": true
    },
    {
      "numeric_code": 1002,
      "alias": "RRHH",
      "name": "Recursos Humanos y Talento",
      "email": "rrhh@empresa.local",
      "description": "Gestión de personal y nóminas",
      "is_active": true
    }
  ],
  "users": [
    {
      "username": "ciso_corp",
      "email": "ciso@seguridad.local",
      "first_name": "Marcos",
      "last_name": "Alonso",
      "is_global_admin": true,
      "is_mfa_enforced": true,
      "uo_alias": "SEC-OPS",
      "role": "ADMIN"
    },
    {
      "username": "dpo_global",
      "email": "dpo@empresa.local",
      "first_name": "Clara",
      "last_name": "Vega",
      "is_global_admin": true,
      "is_mfa_enforced": true
    },
    {
      "username": "operador_sec",
      "email": "operador@seguridad.local",
      "first_name": "Carlos",
      "last_name": "García",
      "uo_alias": "SEC-OPS",
      "role": "OPERATOR"
    },
    {
      "username": "auditor_sec",
      "email": "auditor@seguridad.local",
      "first_name": "Laura",
      "last_name": "Méndez",
      "uo_alias": "SEC-OPS",
      "role": "AUDITOR"
    }
  ]
}
```

> **Directivas de Roles y Seguridad:**
> - **Usuarios Departamentales:** Se definen con `uo_alias` (o `uo_numeric_code`) y `role` (`OPERATOR`, `AUDITOR`, `ADMIN`). Sus permisos quedan circunscritos a la malla de su propia UO.
> - **Administradores Globales de Seguridad:** Se definen con `"is_global_admin": true`. Tienen soberanía sobre toda la plataforma y pueden opcionalmente estar adscritos a una UO departamental con rol o actuar de forma transversal sin UO.
> - **Gobernanza 2FA y Contraseñas:** Puede especificarse `"is_mfa_enforced": true` para forzar 2FA individual obligatorio y `"must_change_password": true` para forzar renovación de clave en el siguiente inicio de sesión. Si se omite la contraseña, se genera una clave temporal aleatoria segura y se registra en el historial inmutable de contraseñas (`PasswordHistory`).
> - **Formato Múltiples Membresías:** Si un usuario pertenece a más de una UO, puede utilizar la lista `"memberships": [{"uo_alias": "RRHH", "role": "OPERATOR"}, ...]`.

### 2.2 Ejecución por Línea de Comandos (CLI)
```bash
poetry run python manage.py load_batch ruta/a/estructura.json
```

### 2.3 Ejecución desde el Dashboard Web
1. Inicie sesión en el Dashboard con una cuenta de **Superusuario** o **Administrador Global**.
2. Diríjase a **Unidades Organizativas** (`/dashboard/unidades-organizativas/`) o **Usuarios y Accesos** (`/dashboard/usuarios/`).
3. En la barra superior de acciones, haga clic en el botón:  
   **📥 Carga Masiva (JSON)** (enlace directo: `/dashboard/unidades-organizativas/carga-masiva/`).
4. Seleccione su archivo `.json` estructurado y pulse **Ejecutar Carga Masiva**.  
El proceso es estrictamente idempotente: actualizará registros preexistentes sin duplicarlos y creará las nuevas dependencias y cuentas con sus correspondientes contraseñas y directivas de seguridad.

---

## 3. Procedimiento de Vicisitud (Terminación Manual Anticipada)

Si un emisor detecta un error en el archivo custodiado (ej. destinatario erróneo o documento obsoleto), puede revocar inmediatamente la disponibilidad del archivo:

1. Localice el documento en el Dashboard (`/dashboard/documentos/`).
2. Haga clic en el botón **"Finalizar por Vicisitud"** (o **"Terminar Documento"**).
3. Indique obligatoriamente el motivo formal de la vicisitud (ej. *"Expediente cancelado por el juzgado de origen"*).
4. El microservicio ejecutará de inmediato:
   - Sobrescritura aleatoria (`os.urandom`) del archivo físico en disco y eliminación (Sanitización NIST SP 800-88).
   - Invalidadación de todos los códigos OTP pendientes.
   - Marcado de `is_consumed = True` y registro inmutable del evento `VICISITUD_FINALIZADO` con el usuario actuante y la justificación.

---

## 4. Tareas Programadas y Servicios Recurrentes (Daemons & Cron Jobs)

Para garantizar la higiene criptográfica, el saneamiento de almacenamiento y el cumplimiento de las fechas de caducidad, Arcamitte incluye comandos de gestión diseñados para ejecutarse de forma desatendida mediante `crontab`, `systemd.timer` o tareas programadas de Celery/Dramatiq:

### 4.1 Cierre y Sanitización de Documentos Caducados
Ejecutar periódicamente (ej. cada 15 o 30 minutos):
```bash
*/15 * * * * cd /opt/arcamitte && poetry run python manage.py close_expired_documents >> /var/log/arcamitte/cron_expired.log 2>&1
```
*Identifica todos los documentos cuya fecha `expires_at` haya sido superada, sobrescribe sus binarios con entropía aleatoria (`os.urandom`), desvincula el inodo (NIST SP 800-88) y asienta la vicisitud formal `EXPIRACION_AUTOMATICA`.*

### 4.2 Purga de Tokens OTP y Sesiones Caducadas
Ejecutar diariamente a medianoche:
```bash
0 0 * * * cd /opt/arcamitte && poetry run python manage.py purge_expired_tokens >> /var/log/arcamitte/cron_tokens.log 2>&1
```
*Elimina de la base de datos los códigos OTP y tokens de acceso cuyo plazo de validez ha expirado.*

---

## 5. Sellado de Tiempo Cualificado RFC 3161 y Preservación de Evidencias

Arcamitte soporta integración con Autoridades de Sellado de Tiempo (TSA) cualificadas conforme a eIDAS / RFC 3161:
- Cada exportación certificada del libro de auditoría forense (`/dashboard/auditoria/exportar/`) genera un recibo criptográfico con hash SHA-256 inmutable (`AuditExportReceipt`).
- Si `ARCAMITTE_RFC3161_ENABLED = True`, el microservicio envía el hash del archivo exportado a la TSA configurada y adjunta la respuesta sellada (`.tsr`) en formato base64.
- La integridad de cualquier recibo o extracto forense puede verificarse matemáticamente en tiempo real desde el Dashboard (`/dashboard/auditoria/recibos/verificar/`).
