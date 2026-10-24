# Manual de Operaciones y Administración de Arcamitte

Esta guía está dirigida a Oficiales de Seguridad de la Información (CISO), Administradores de Sistemas y Operadores departamentales responsables del despliegue y mantenimiento de **Arcamitte**.

---

## 1. Acceso y Paneles de Control

Arcamitte ofrece dos consolas administrativas con separación de propósitos:

### 1.1 Cyber-Ops Bespoke Dashboard (`/dashboard/`)
Panel de control visual moderno con tema oscuro, desarrollado sobre Bootstrap 5 nativo sin librerías invasivas externas, optimizado para operaciones diarias:
- **Resumen Ejecutivo (KPIs):** Conteo de documentos bajo custodia activa, archivos consumidos y sanitizados, UOs registradas y volumen de eventos.
- **Gestor Documental:** Listado paginado con filtros por UO y estado, buscador en tiempo real por nombre de archivo o hash SHA-256.
- **Subida Segura:** Asistente de custodia con cálculo de hash en cliente, selección de UO emisora/receptora y política de destrucción.
- **Detalle y Auditoría:** Inspección de metadatos, línea temporal de eventos y finalización anticipada por vicisitud.
- **Gestión de UOs y Miembros:** Alta y edición de unidades organizativas y asignación de usuarios con roles de Operador, Auditor o Administrador de UO.
- **Directorio de Usuarios:** Creación y modificación de cuentas con contraseñas temporales automáticas de alta entropía.
- **Pasarela de Tokens API:** Generación de credenciales M2M con scopes específicos y revocación inmediata.

### 1.2 Matriz de Roles y Atribuciones

| Rol | Cifrar y Tramitar | Consultar Asientos | Descarga de Auditoría Forense Preservada | Terminar y Destruir Asiento | Gestión de Personal UO | Gobernanza Global |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Operador** | ✅ Sí | ✅ Sí (de su UO) | ❌ No | ❌ No | ❌ No | ❌ No |
| **Auditor** | ✅ Sí | ✅ Sí (de su UO) | ✅ **Sí (Exclusivo UO)** | ❌ No | ❌ No | ❌ No |
| **Admin de UO** | ✅ Sí | ✅ Sí (de su UO) | ✅ Sí (de su UO) | ✅ **Sí (Solo de su UO)** | ✅ Sí | ❌ No |
| **Superusuario** | ✅ Sí | ✅ Sí (Global) | ✅ Sí (Global) | ✅ **Sí (Cualquier asiento)** | ✅ Sí | ✅ Sí |

#### Claves Operativas de los Roles:
- **Operador (`Role.OPERATOR`):** Cifra y envía trámites. No tiene acceso a descargas periciales ni a la destrucción manual anticipada de asientos.
- **Auditor (`Role.AUDITOR`):** Puede realizar **Descargas de Auditoría Forense Preservadas** para peritajes o requerimientos legales sin consumir el asiento ni alterar el archivo en disco (evento `ADMIN_DESCARGA_PRESERVADA`).
- **Administrador de UO (`Role.ADMIN`):** Administra el personal de su UO (altas, roles, reseteo de claves) y puede destruir/finalizar anticipadamente asientos de su UO.
- **Superusuario:** Soberanía completa sin restricciones de departamento.

### 1.3 Panel Django Clásico (`/admin/`)
Panel administrativo oficial con controles reforzados para superusuarios:
- **Importación Masiva JSON:** Carga conjunta de departamentos y usuarios.
- **Inmutabilidad Reforzada:** Deshabilitación de borrados directos para garantizar la integridad probatoria y la cadena de custodia.

---

## 2. Aprovisionamiento Masivo mediante JSON

Para dar de alta estructuras organizativas complejas de forma rápida e idempotente, Arcamitte incluye un motor de importación por lotes.

### 2.1 Formato del Archivo JSON
Cree un archivo con la estructura:
```json
{
  "organizational_units": [
    {
      "numeric_code": 1001,
      "name": "Dirección de Ciberseguridad",
      "alias": "SEC-OPS"
    },
    {
      "numeric_code": 1002,
      "name": "Recursos Humanos y Talento",
      "alias": "RRHH"
    }
  ],
  "users": [
    {
      "username": "operador_sec",
      "email": "operador@seguridad.local",
      "first_name": "Carlos",
      "last_name": "García",
      "is_staff": true,
      "memberships": [
        {
          "uo_code": 1001,
          "role": "OPERADOR"
        }
      ]
    },
    {
      "username": "auditor_sec",
      "email": "auditor@seguridad.local",
      "first_name": "Laura",
      "last_name": "Méndez",
      "is_staff": true,
      "memberships": [
        {
          "uo_code": 1001,
          "role": "AUDITOR"
        }
      ]
    }
  ]
}
```

### 2.2 Ejecución por Línea de Comandos (CLI)
```bash
poetry run python manage.py load_batch ruta/a/estructura.json
```

### 2.3 Ejecución desde la Web
Acceda a `/admin/arcamitte/organizationalunit/import-batch/`, seleccione el archivo JSON y confirme la importación. El proceso es estrictamente idempotente: no duplicará departamentos ni usuarios existentes.

---

## 3. Procedimiento de Vicisitud (Terminación Manual Anticipada)

Si un emisor detecta un error en el archivo custodiado (ej. destinatario erróneo o documento obsoleto), puede revocar inmediatamente la disponibilidad del archivo:

1. Localice el documento en el Dashboard (`/dashboard/documents/`) o en el Admin.
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
0 0 * * * cd /opt/arcamitte && poetry run python manage.py purge_expired_tokens --days 1 >> /var/log/arcamitte/cron_purge.log 2>&1
```
*Elimina de la base de datos los registros de verificación temporal cuya validez de 15 minutos haya expirado o ya hayan sido utilizados, evitando el engrosamiento innecesario de las tablas en alta concurrencia.*

### 4.3 Configuración como Servicio y Temporizador en `systemd` (Recomendado en Producción)

Para mayor robustez y trazabilidad en servidores Linux modernos (journalctl, autorestart), configure unidades de `systemd`:

`/etc/systemd/system/arcamitte-expired.service`:
```ini
[Unit]
Description=Arcamitte - Purga y Sanitizacion de Documentos Caducados
After=network.target

[Service]
Type=oneshot
User=arcamitte
WorkingDirectory=/opt/arcamitte
ExecStart=/usr/local/bin/poetry run python manage.py close_expired_documents
StandardOutput=journal
StandardError=journal
```

`/etc/systemd/system/arcamitte-expired.timer`:
```ini
[Unit]
Description=Ejecutar Arcamitte Expired cada 15 minutos

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

Habilitar el temporizador:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now arcamitte-expired.timer
```

---

## 5. Diagnóstico y Pruebas Operativas

### Comprobar Entrega de Correo SMTP
```bash
poetry run python manage.py test_smtp --recipient test@empresa.com
```

### Descifrado Forense de Emergencia (Solo Superusuarios)
En situaciones de litigio o requerimiento judicial, un auditor autorizado puede recuperar un documento que aún se encuentre bajo custodia:
```bash
poetry run python manage.py decrypt_document <SHA256_HASH> --output /tmp/recuperado.pdf
```
*Esta operación genera automáticamente una entrada en el log de auditoría (`DESCARGA_AUDITORIA`).*
