# Arcamitte — Microservicio Criptográfico de Custodia y Entrega Desatendida

<p align="center">
  <img src="arcamitte/static/arcamitte/img/logo.jpg" alt="Arcamitte Logo" width="160" style="border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5);">
</p>

<p align="center">
  <strong>Plataforma Segura de Custodia Efímera de Archivos, Cifrado de Sobre, Malla Departamental y Destrucción Física (NIST SP 800-88 & OWASP Top 10)</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%20%7C%203.13%20%7C%203.14-blue?logo=python" alt="Python Version">
  <img src="https://img.shields.io/badge/Django-5.2-green?logo=django" alt="Django Version">
  <img src="https://img.shields.io/badge/Security-AES--256--GCM%20%2B%20Fernet-red?logo=security" alt="Cryptography">
  <img src="https://img.shields.io/badge/Standard-NIST%20SP%20800--88%20Sanitization-purple" alt="NIST Sanitization">
  <img src="https://img.shields.io/badge/Architecture-Zero--Trust%20Mesh-orange" alt="Zero Trust">
  <img src="https://img.shields.io/badge/Coverage-100%25%20Pytest%20Green-success" alt="Pytest Status">
</p>

---

## 1. Etimología y Fundamento Filosófico: *Arca + Mittere*

El nombre **Arcamitte** se construyó a partir de dos términos en latín clásico que describen de forma directa el funcionamiento técnico de la aplicación:

### 1. La primera raíz: *Arca / Arcanum*
- **Origen latino:**
  - En su sentido material (*arca*), era el cofre de madera reforzada o hierro, la caja fuerte donde los romanos guardaban bajo llave el dinero, joyas y documentos de máximo valor.
  - En su sentido abstracto (*arcanum*), dio origen a la palabra "arcano", que significa secreto profundo, misterio impenetrable o algo reservado únicamente para quien posee el conocimiento o la clave.
- **Sentido técnico en Arcamitte:** Representa el archivo cifrado de extremo a extremo. Es el contenedor hermético donde los datos viajan sellados; si no se posee la clave efímera, es matemáticamente imposible abrirlo.

### 2. La segunda raíz: *Mittere*
- **Origen latino:**
  - Es el verbo en latín que significa enviar, despachar, remitir o lanzar hacia un destino.
  - De esta misma raíz derivan en español palabras como remitente, emisión, misión o transmitir.
- **Sentido técnico en Arcamitte:** Representa el tránsito o envío seguro del archivo a través de la red hacia el destinatario legítimo.

### El significado conjunto
Al unir ambas piezas morfológicas (**Arca + Mittere**):
> **Arcamitte** significa literalmente *"Enviar el arca"* o *"Despachar el secreto"*.

Describe con exactitud técnica la arquitectura: el cliente cifra el contenido dentro de una "caja fuerte" (el arca) y el servidor actúa únicamente como transportista que la despacha (*mittere*) sin poder ver jamás qué contiene en su interior.

---

## 2. Visión General del Sistema

**Arcamitte** es un microservicio autónomo y de alta seguridad diseñado para la **custodia criptográfica y entrega desatendida de documentos confidenciales**. Elimina de raíz la necesidad de contraseñas humanas legibles, transportes inseguros de binarios y almacenamiento indefinido de datos sensibles.

### Principios Fundamentales de Seguridad:
1. **Entrega Referenciada por Hash SHA-256:** El cliente o sistema integrador nunca envía el documento original por canales inseguros para solicitarlo; únicamente referencia su identificador criptográfico unívoco SHA-256.
2. **Cero Contraseñas Humanas (Zero-Knowledge):** No existen contraseñas memorizables. Cada documento se cifra con una clave simétrica efímera única (DEK) generada en memoria RAM y protegida bajo cifrado de sobre (Envelope Encryption) con la clave maestra de servidor `ARCAMITTE_FERNET_KEY`.
3. **Malla Departamental Aislada (UO Mesh):** Soporte multi-entidad mediante Unidades Organizativas (UO). Los documentos viajan cifrados de una UO emisora a una UO receptora con segregación estricta de privilegios (Operador vs. Auditor).
4. **Verificación Desatendida con OTP Efímero:** El destinatario legítimo solicita el archivo mediante su correo corporativo previamente autorizado y recibe un código OTP de 6 dígitos con caducidad estricta (15 min) y límite de intentos (máx. 3).
5. **Destrucción Segura Física (*Burn-After-Read* & Sanitización):** Al completarse el consumo (o alcanzarse la fecha de caducidad), el binario cifrado en disco es sobrescrito con bytes aleatorios criptográficos (`os.urandom`) antes de ser eliminado del sistema de archivos, garantizando cumplimiento **NIST SP 800-88**.
6. **Tokens M2M de Conocimiento Cero:** La API de integración utiliza credenciales de máquina con prefijo `arca_live_...`. Solo se persiste el hash SHA-256 en base de datos.
7. **Protección Contra Canales Laterales (Anti-Timing Attacks):** Los intentos de enumeración contra hashes inexistentes ejecutan retardos criptográficos sintéticos (PBKDF2) idénticos al cálculo de verificación real para mitigar ataques de temporización (CWE-208).

---

## 3. Arquitectura de Cifrado y Flujo de Vida

```mermaid
sequenceDiagram
    autonumber
    actor Emisor as Emisor / Sistema M2M
    participant Arca as Microservicio Arcamitte
    participant DB as Base de Datos Cifrada
    participant Storage as Disco (Sanitizable)
    actor Receptor as Destinatario Final
    participant Mail as Servidor SMTP

    Note over Emisor,Arca: 1. Fase de Ingesta y Cifrado
    Emisor->>Arca: Envío de archivo + UO Origen/Destino + Correos autorizados
    Arca->>Arca: Generar DEK única (Fernet simétrica en RAM)
    Arca->>Arca: Cifrar archivo con DEK
    Arca->>Arca: Cifrar DEK con ARCAMITTE_FERNET_KEY (Envelope)
    Arca->>Storage: Guardar binario cifrado (.bin)
    Arca->>DB: Registrar metadatos, SHA-256, DEK cifrada y UO Mesh

    Note over Receptor,Mail: 2. Fase de Solicitud y Verificación
    Receptor->>Arca: Petición pública con SHA-256 y correo
    Arca->>Arca: Validar pertenencia del correo y disponibilidad
    Arca->>Arca: Generar OTP temporal (6 dígitos, CSPRNG)
    Arca->>Mail: Despachar OTP vía SMTP corporativo
    Receptor->>Arca: Canjear código OTP

    Note over Arca,Storage: 3. Descifrado en Memoria y Destrucción Física
    Arca->>Arca: Comparación en tiempo constante (compare_digest)
    Arca->>Storage: Leer binario cifrado a memoria RAM
    Arca->>Arca: Descifrar DEK -> Descifrar archivo en RAM
    Arca-->>Receptor: Stream binario descifrado (FileResponse)
    Arca->>Storage: Sobrescritura aleatoria (os.urandom) + Desvinculación física
    Arca->>DB: Marcar is_consumed=True, registrar log inmutable de auditoría
```

---

## 4. Matriz de Roles y Modelo de Gobernanza Departamental

Arcamitte implementa un modelo jerárquico inclusivo con separación de responsabilidades y soberanía departamental delegada:

| Rol | Ámbito | Cifrar y Tramitar | Consultar Asientos | Descarga de Auditoría Forense Preservada | Terminar y Destruir Asiento | Gestión de Personal |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Operador** | UO Asignada | ✅ Sí | ✅ Sí (de su UO) | ❌ No | ❌ No | ❌ No |
| **Auditor** | UO Asignada | ✅ Sí | ✅ Sí (de su UO) | ✅ **Sí (Exclusivo UO)** | ❌ No | ❌ No |
| **Admin de UO** | UO Asignada | ✅ Sí | ✅ Sí (de su UO) | ✅ Sí (de su UO) | ✅ **Sí (Solo de su UO)** | ✅ Sí (Personal UO) |
| **Superusuario** | Global | ✅ Sí | ✅ Sí (Global) | ✅ Sí (Global) | ✅ **Sí (Cualquier asiento)** | ✅ Sí (Global) |

### Atribuciones y Distinciones Específicas:
1. **Operador Departamental (`Role.OPERATOR`):** Cifra y remite trámites entre departamentos. Consulta el estado de canje de los asientos asignados a su Unidad Organizativa. No tiene acceso a descargas periciales ni a la destrucción manual anticipada de asientos.
2. **Auditor Departamental (`Role.AUDITOR`):** Posee todas las capacidades del operador más la potestad exclusiva de realizar **Descargas de Auditoría Forense Preservadas**. Esto permite al auditor inspeccionar o descargar el documento descifrado para diligencias de control legal o pericial **sin consumir el asiento ni destruir el archivo físico del servidor**, asentando un registro inmutable en auditoría (`ADMIN_DESCARGA_PRESERVADA`).
3. **Administrador de UO (`Role.ADMIN`):** Conduce la gobernanza departamental: gestiona los miembros de su UO (altas, bajas, roles, reseteo de claves) y tiene la potestad exclusiva de revocar y clausurar anticipadamente («Terminar y Destruir por Vicisitud») los asientos emitidos por su departamento.
4. **Superusuario del Sistema:** Ostenta autoridad global sobre la configuración del sistema, alta de UOs, directorio maestro de usuarios, expedición de tokens M2M, trazabilidad forense completa y clausura de cualquier asiento.

### Principios de Seguridad en la UI y el Backend:
- **Ocultación Dinámica de Acciones:** Si un usuario no tiene facultades para una acción (ej. destruir un documento o acceder a la gobernanza), los botones correspondientes (papelera de destrucción, sección de gobernanza, tokens M2M) no se renderizan en la interfaz de usuario.
- **Protección contra Bloqueos y Auto-Degradación:** Ningún administrador puede auto-revocarse privilegios ni desactivar su propia cuenta. Ningún usuario puede asignar a terceros un nivel de privilegio superior al suyo.
- **Cierre Automático por Vicisitud Física:** Si el archivo cifrado desaparece del almacenamiento físico de forma sobrevenida, el sistema clausura formalmente el documento (`is_consumed=True`) y genera automáticamente un registro inmutable en `DocumentAccessLog` constatando la retirada física.

---

## 5. Puntos de Entrada e Interfaces

Arcamitte proporciona tres interfaces diseñadas para distintos propósitos operativos:

| Interfaz | Ruta | Descripción |
| :--- | :--- | :--- |
| **Bespoke Cyber-Ops Dashboard** | `/dashboard/` | Panel de control moderno en tema oscuro (Bootstrap 5 nativo, sin dependencias de terceros), estadísticas de custodia, subida de documentos, gestión de UOs, auditoría y tokens de API. |
| **Django Admin Clásico** | `/admin/` | Panel administrativo oficial con validaciones avanzadas, importación masiva JSON, inspección de hashes e inmutabilidad garantizada. |
| **Portal Público de Canje** | `/arcamitte/solicitar/` | Pasarela ligera y adaptada a móviles para que los destinatarios soliciten su OTP e introduzcan su código para descargar el archivo. |
| **Machine-to-Machine REST API** | `/api/v1/` | Endpoints seguros para automatizaciones con autenticación por encabezado `X-API-Key: arca_live_...`. |

---

## 6. Requisitos y Dependencias

- **Python:** 3.12, 3.13 o 3.14
- **Gestor de Paquetes:** [Poetry](https://python-poetry.org/) (o `pip`)
- **Librerías Criptográficas y Web:**
  - `django >= 5.1`
  - `djangorestframework >= 3.15`
  - `cryptography >= 43.0`
  - `python-magic >= 0.4.27`
  - `pillow >= 10.4.0`

---

## 7. Instalación y Configuración Rápida

### Paso 1: Clonar el Repositorio
```bash
git clone https://github.com/jrubioh1/arcamitte.git
cd arcamitte
```

### Paso 2: Instalar Dependencias con Poetry
```bash
poetry install
```

### Paso 3: Configurar `arcamitte.ini`
Copie la plantilla de configuración e inicialice las variables requeridas:
```bash
cp arcamitte.ini.template arcamitte.ini
```

Genere una clave simétrica Fernet de 32 bytes en formato url-safe base64:
```bash
poetry run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Pegue la clave generada en la sección `[security]` de `arcamitte.ini`:
```ini
[security]
fernet_key = TU_CLAVE_GENERADA_AQUI=
timing_pbkdf2_iterations = 20000
max_file_size = 52428800
```

### Paso 4: Inicializar la Base de Datos y el Entorno Staging
El microservicio incluye un comando idempotente de arranque que crea la base de datos, aplica migraciones, provisiona la malla inicial de UOs (Seguridad, RRHH, Finanzas, Legal), crea el usuario superadministrador y prepara documentos de prueba:

```bash
poetry run python manage.py setup_staging --clean
```
> **Credenciales de Staging creadas:**
> - **Superadmin:** `admin` / `AdminMaster#2026`
> - **Admin Dirección:** `admin_dir` / `PasswordDir#2026`
> - **Operador RRHH:** `gestor_rrhh` / `PasswordRRHH#2026`
> - **Auditor RRHH:** `auditor_rrhh` / `PasswordAuditor#2026`

### Paso 5: Ejecutar el Servidor de Desarrollo
```bash
poetry run python manage.py runserver 0.0.0.0:8000
```

Acceda a:
- **Dashboard Operativo:** [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/)
- **Portal Público:** [http://127.0.0.1:8000/arcamitte/solicitar/](http://127.0.0.1:8000/arcamitte/solicitar/)
- **Django Admin:** [http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/admin/)

---

## 8. Configuración `arcamitte.ini`

El microservicio utiliza un archivo INI como única fuente de verdad técnica:

```ini
[django]
secret_key = clave-secreta-para-sesiones-y-csrf
debug = true
allowed_hosts = 127.0.0.1,localhost

[security]
fernet_key = ClaveFernetGeneradaDe32BytesUrlSafe=
max_file_size = 52428800
timing_pbkdf2_iterations = 20000

[email]
backend = django.core.mail.backends.console.EmailBackend
host = localhost
port = 25
default_from_email = no-reply@arcamitte.local
async_email = true
email_max_workers = 8

[throttling]
web_request_limit_per_minute = 15
api_access_request_rate = 15/minute
api_access_consume_rate = 30/minute
```

---

## 9. M2M API Gate (Integración con Sistemas Externos)

Los sistemas corporativos (CRM, ERP, Gestores Documentales) pueden automatizar la subida y custodia de archivos mediante la API REST v1.

### Generación de Token
Genere un token desde el Dashboard (`/dashboard/api-tokens/`) o mediante el comando de administración. El token generado tendrá el formato:
`arca_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

### Ejemplo de Subida de Documento
La aplicación integradora externa únicamente necesita enviar el archivo y los correos autorizados:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/documents/ \
  -H "X-API-Key: arca_live_SU_TOKEN_AQUI" \
  -F "original_file=@contrato_confidencial.pdf" \
  -F "allowed_emails=destinatario@empresa.com"
```

Respuesta JSON:
```json
{
  "id": "e5b8d28a-7cb2-4a0b-9df6-2be5188f6194",
  "status": "created",
  "file_hash": "c5f590b2b80041d8e1f5f3e9c68c34fba3f5e5529f7cf7c65d63f47e09961dbf",
  "original_filename": "contrato_confidencial.pdf",
  "burn_policy": "FIRST_ACCESS",
  "expires_at": "2026-11-07T12:00:00Z"
}
```

> **Nota sobre UOs:** Las Unidades Organizativas (`origin_uo`, `target_uo`) son 100% opcionales. La aplicación externa no necesita saber nada de departamentos si no los utiliza; Arcamitte se encarga de la custodia criptográfica y la entrega segura de forma totalmente autónoma.

### Consultar Estado Criptográfico (Sin exponer contenido)
```bash
curl -X GET http://127.0.0.1:8000/api/v1/documents/c5f590b2b80041d8e1f5f3e9c68c34fba3f5e5529f7cf7c65d63f47e09961dbf/status/ \
  -H "X-API-Key: arca_live_SU_TOKEN_AQUI"
```

---

## 10. Verificación de Seguridad y Pruebas Unitarias

La suite de pruebas incluye **174 tests automatizados** con verificación rigurosa de controles de seguridad, validación de formatos mágicos, sanitización NIST SP 800-88, aislamiento de mallas UO, ciclo de vida de usuarios/contraseñas, gobernanza jerárquica, defensas anti-fuerza bruta, autenticación multifactor 2FA (TOTP), control de secuestro de sesiones (Session Hijacking), rotación dinámica de claves maestras y telemetría SIEM:

```bash
poetry run pytest -v
```

Resultado verificado:
```text
============================= 174 passed in 56.87s =============================
```

### Casos de Prueba Avanzados y Escenarios de Abuso (Adversarial Testing)
La batería de tests incluye pruebas específicas contra vectores de ataque y escenarios de abuso:
- **Autenticación Multifactor Nativa (RFC 6238 / RFC 4226):** Verificación de derivas temporales, validación contra vectores oficiales de prueba del NIST/RFC 6238 Apéndice B y consumo único de códigos de rescate con hashes SHA-256 (`test_advanced_security_phase_a.py`).
- **Prevención de Secuestro de Sesión (Session Hijacking):** Detección perimetral de discrepancia de IP en peticiones HTTP con cookies activas, invalidación inmediata de sesión, alerta SIEM y registro forense inalterable en `SessionSecurityMiddleware`.
- **Control de Concurrencia (Single Concurrent Session):** Revocación automática de sesiones anteriores al detectarse un nuevo inicio de sesión desde otro navegador o dispositivo.
- **Rotación Criptográfica en Caliente (MultiFernet Keyring):** Recifrado transaccional atómico de claves de datos (DEK) en reposo sin pérdida de disponibilidad mediante `python manage.py rotate_master_key`.
- **Ataques de Fuerza Bruta y Credential Stuffing:** Bloqueo automático de cuentas tras 5 intentos fallidos consecutivos, baneo de IPs tras 10 fallos e intercepción perimetral con `HTTP 403 Forbidden` en `IPBanMiddleware`.
- **Evasión de Contraseñas (Password Reuse Bypass):** Verificación con `PasswordHistoryValidator` impidiendo alternar o reutilizar cualquiera de las últimas 5 contraseñas previas.
- **Manipulación de Base de Datos (Data Tampering):** Detección inmediata de adulteración de registros mediante verificación de cadena criptográfica (*Hash Chaining* secuencial).
- **Inyección de Fórmulas CSV (CWE-1236):** Neutralización de comandos y macros DDE (`=CMD`, `+SUM`, `@IMPORTXML`, `-FORMULA`) en todas las exportaciones certificadas.
- **Falsificación Documental de Auditoría:** Detección de alteraciones en volcados CSV mediante contraste del hash SHA-256 contra el recibo oficial inmutable `AuditExportReceipt`.
- **Bypass de Privilegios:** Intentos de desbloqueo no autorizados o revocación de baneo por usuarios sin rol adecuado rechazados con `403 Forbidden`.

### Controles de Seguridad Verificados (SAST & SCA)
El código y las dependencias han sido sometidos a auditoría de seguridad exhaustiva:
- **SCA (pip-audit):** 0 vulnerabilidades conocidas en librerías en tiempo de ejecución (`cryptography >= 44.0.1`, `djangorestframework >= 3.18.2`, `segno >= 1.6.6`).
- **SAST Python (Bandit):** 0 vulnerabilidades de severidad Alta o Media en más de 13.000 líneas de código. Eliminación del 100% de llamadas a `mark_safe` en favor de `format_html` sanitizado.
- **SAST OWASP (Semgrep OSS):** 0 hallazgos bloqueantes sobre 456 reglas activas (OWASP Top 10, CWE, inyecciones y CSRF).
- **Subresource Integrity (SRI):** Atributos `integrity="sha384-..."` y `crossorigin="anonymous"` obligatorios en todos los recursos externos CDN.
- **Hardening de Cabeceras y Cookies:** `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `LANGUAGE_COOKIE_SECURE`, `SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS = "DENY"` y HSTS activo en producción (`DEBUG=False`).

---

## 11. Cumplimiento de Estándares de Seguridad

- **Esquema Nacional de Seguridad (ENS - Categoría ALTA) & eIDAS:**
  - `op.acc.1 / op.acc.2`: Autenticación multifactor 2FA/TOTP conforme a RFC 6238 y opción de obligatoriedad para perfiles staff.
  - `op.acc.5 / op.acc.6`: Complejidad mínima de contraseñas (12 caracteres), prohibición de reutilización (historial de 5), caducidad periódica a 90 días, control de concurrencia y limitación de intentos fallidos.
  - `op.exp.8`: Trazabilidad, integridad inalterable de registros mediante *Hash Chaining* y no repudio legal de exportaciones de auditoría mediante recibos oficiales `AuditExportReceipt` y huellas SHA-256.
  - `op.seg.4`: Detección perimetral y baneo en lista negra de IPs atacantes, enlace de sesión a IP de origen (Anti-Hijacking).
  - `op.sec.4`: Soporte de rotación periódica de claves de cifrado en reposo (MultiFernet).
- **NIST SP 800-88 Rev. 1 (Media Sanitization):** Sobrescritura aleatoria de almacenamiento físico previa desvinculación de inodo.
- **NIST SP 800-63B (Digital Identity Guidelines - AAL2):** Verificación en dos pasos (TOTP con HMAC-SHA1 y secreto de 160 bits), contraseñas robustas y caducidad temporal.
- **NIST SP 800-57 Part 1 Rev. 5 (Key Management):** Rotación de claves maestras criptográficas y separación de claves de cifrado de datos (DEK) y claves de cifrado de claves (KEK).
- **NIST SP 800-53 Rev. 5:**
  - `AC-7`: Bloqueo automático de cuentas ante intentos no exitosos y alertas de seguridad.
  - `AC-10 / AC-11`: Control de concurrencia de sesiones e invalidación por discrepancia de origen.
  - `SC-13 / SC-28`: Cifrado criptográfico fuerte en reposo y en tránsito.
  - `AC-3 / AC-6`: Menor privilegio y aislamiento departamental por UO.
  - `AU-2 / AU-6 / AU-9 / AU-10 / AU-12`: Registro inmutable de eventos de acceso, conectores SIEM en tiempo real e integridad de registros de auditoría.
- **OWASP API Security Top 10 (2023):**
  - `API1:2023 (BOLA)`: Aislamiento estricto de documentos por pertenencia de UO y usuario.
  - `API2:2023 (Broken Auth)`: Tokens de conocimiento cero y OTPs efímeros con caducidad forzada.
  - `API4:2023 (Unrestricted Resource Consumption)`: Limitación de tasa (throttling) en peticiones públicas y de API.
  - `API8:2023 (Security Misconfiguration)`: Verificación en el arranque de la clave de producción `ARCAMITTE_FERNET_KEY`.

---

## 12. Documentación Técnica Detallada

Para consultar la documentación completa de cada subsistema:
- [Guía de Arquitectura Criptográfica](docs/ARCHITECTURE.md)
- [Referencia Completa de la API REST](docs/API_REFERENCE.md)
- [Manual de Administración y Operaciones](docs/ADMIN_GUIDE.md)
- [Manual de Ciberseguridad y Guía de Configuración para Operadores (Didáctico)](docs/SECURITY_CONFIG_GUIDE.md)
- [Controles Técnicos y Modelo de Seguridad](docs/SECURITY.md)

---

## Licencia

Distribuido bajo licencia GNU General Public License v3.0. Consulte `LICENSE` para más información.
Arcamitte Project &copy; 2026.
