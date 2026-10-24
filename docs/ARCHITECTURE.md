# Arquitectura del Sistema Arcamitte

Este documento detalla la arquitectura técnica, los componentes internos, el flujo criptográfico de Cifrado de Sobre (*Envelope Encryption*), el aislamiento de malla departamental (*UO Mesh*), la política de borrado seguro (*Burn-After-Read / Sanitización NIST SP 800-88*) y el subsistema de auditoría inmutable de **Arcamitte**.

---

## 0. Etimología y Fundamento Arquitectónico: *Arca + Mittere*

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

## 1. Visión Arquitectónica y Capas de Servicio

Arcamitte está concebido como un microservicio autónomo y desacoplado estructurado en capas estrictamente delimitadas:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CAPA DE ENTRADA Y ACCESO                        │
│                                                                        │
│  [ Dashboard Web GUI ]   [ Portal Público OTP ]    [ REST API v1 Gate ]│
│     /dashboard/...        /arcamitte/solicitar/        /api/v1/...     │
│                           /arcamitte/canjear/                          │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                  CAPA DE SEGURIDAD Y AUTENTICACIÓN                     │
│                                                                        │
│  [ Zero-Knowledge Tokens ]  [ Throttling / Anti-Flood ]  [ RBAC / UO ] │
│    APIToken (SHA-256)        AnonRateThrottle (Cache)     IsAuthenticated│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                 CAPA DE SERVICIOS CRIPTOGRÁFICOS Y NEGOCIO             │
│                                                                        │
│  [ arcamitte.services ]                                                │
│    • Envelope Encryption (DEK + ARCAMITTE_FERNET_KEY)                  │
│    • NIST SP 800-88 File Sanitization (os.urandom shredder)           │
│    • Anti-Timing PBKDF2 Dummy Compute Engine                           │
│    • OTP Lifecycle & Burn Policy Coordinator                           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                   CAPA DE PERSISTENCIA Y AISLAMIENTO                   │
│                                                                        │
│  [ UO Mesh Multi-Tenant ]      [ Metadatos & DEK ]   [ Audit Engine ]  │
│    OrganizationalUnit           EncryptedDocument     DocumentAccessLog│
│    UserUOMembership                                  (WORM inmutable)  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Flujo Criptográfico: Cifrado de Sobre (*Envelope Encryption*)

Arcamitte aplica el patrón criptográfico de **Cifrado de Sobre** recomendado por NIST y CIS:

### 2.1 Clave de Datos por Documento (DEK - Data Encryption Key)
1. Para cada documento subido al sistema, se genera en memoria RAM una clave simétrica única mediante un generador criptográficamente seguro (CSPRNG):
   ```python
   dek = Fernet.generate_key()
   ```
2. El archivo original en claro es cifrado en memoria usando esta DEK efímera (utilizando AES-128-CBC autenticado con HMAC-SHA256 bajo el estándar Fernet).
3. El binario cifrado se almacena en el sistema de archivos con extensión `.bin` y permisos restringidos. En ningún momento se guarda el archivo en claro en disco.

### 2.2 Clave Maestra del Servidor (KEK - Key Encryption Key)
1. La DEK generada en RAM nunca se almacena en texto plano en la base de datos.
2. La DEK es cifrada en memoria utilizando la clave maestra del servidor `ARCAMITTE_FERNET_KEY`:
   ```python
   server_fernet = Fernet(ARCAMITTE_FERNET_KEY)
   encrypted_dek = server_fernet.encrypt(dek).decode("utf-8")
   ```
3. El valor resultante (`encrypted_dek`) se guarda en la base de datos junto a los metadatos del documento.
4. Para descifrar el documento, el servidor requiere de ambas piezas:
   - La `encrypted_dek` almacenada en base de datos.
   - La clave `ARCAMITTE_FERNET_KEY` custodiada en variables de entorno o archivo de configuración local.

---

## 3. Destrucción Física Segura (NIST SP 800-88 Rev. 1)

Cuando un documento cumple su ciclo de vida (canjeado bajo política *Burn-After-Read*, caducado o terminado por vicisitud), Arcamitte ejecuta una sanitización física del medio de almacenamiento antes de liberar el inodo del sistema de archivos:

```python
def shred_and_delete_file(file_path: Union[str, Path]) -> bool:
    path = Path(file_path)
    if not path.is_file():
        return False
    
    file_size = path.stat().st_size
    # Paso 1: Sobrescritura física con entropía aleatoria criptográfica
    with open(path, "wb") as f:
        f.write(os.urandom(file_size))
        f.flush()
        os.fsync(f.fileno())  # Fuerza el volcado físico a los platos/bloques de almacenamiento
    
    # Paso 2: Desvinculación del inodo a nivel de sistema operativo
    path.unlink()
    return True
```

Esto impide la recuperación forense de datos residuales en sectores no reasignados.

---

## 4. Arquitectura de Malla Departamental (*UO Mesh*)

Arcamitte organiza el acceso institucional mediante **Unidades Organizativas (UO)** formando una malla segura:

### 4.1 Dimensiones de la Malla
- **UO Emisora (`origin_uo`):** El departamento que custodia y sube el archivo confidencial.
- **UO Receptora (`target_uo`):** El departamento facultado para recibir, gestionar y auditar el documento.

### 4.2 Modelo de Roles y Matriz de Atribuciones
Los usuarios se asocian a las UOs mediante la entidad `UserUOMembership` definiendo su rol operativo:

| Rol | Ámbito | Cifrar y Tramitar | Consultar Asientos | Descarga de Auditoría Forense Preservada | Terminar y Destruir Asiento | Gestión de Personal UO |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Operador (`OPERATOR`)** | UO Asignada | ✅ Sí | ✅ Sí (de su UO) | ❌ No | ❌ No | ❌ No |
| **Auditor (`AUDITOR`)** | UO Asignada | ✅ Sí | ✅ Sí (de su UO) | ✅ **Sí (Exclusivo UO)** | ❌ No | ❌ No |
| **Admin de UO (`ADMIN`)** | UO Asignada | ✅ Sí | ✅ Sí (de su UO) | ✅ Sí (de su UO) | ✅ **Sí (Solo de su UO)** | ✅ Sí (Personal UO) |
| **Superusuario** | Global | ✅ Sí | ✅ Sí (Global) | ✅ Sí (Global) | ✅ **Sí (Cualquier asiento)** | ✅ Sí (Global) |

#### Distinciones Operativas Clave:
1. **Operador:** Cifra y remite trámites entre departamentos. Consulta el estado de canje de los asientos asignados a su Unidad Organizativa. No tiene acceso a descargas periciales ni a la destrucción manual anticipada de asientos.
2. **Auditor:** Posee todas las facultades del operador más la potestad exclusiva de realizar **Descargas de Auditoría Forense Preservadas**. Esto permite al auditor inspeccionar o descargar el documento descifrado para diligencias de control legal o pericial **sin consumir el asiento ni destruir el archivo físico del servidor**, asentando un registro inmutable en auditoría (`ADMIN_DESCARGA_PRESERVADA`).
3. **Administrador de UO:** Conduce la gobernanza departamental: gestiona los miembros de su UO (altas, bajas, roles, reseteo de claves) y tiene la potestad exclusiva de revocar y clausurar anticipadamente («Terminar y Destruir por Vicisitud») los asientos emitidos por su departamento.
4. **Superusuario del Sistema:** Ostenta autoridad global sobre la configuración del sistema, alta de UOs, directorio maestro de usuarios, expedición de tokens M2M, trazabilidad forense completa y clausura de cualquier asiento.

### 4.3 Salvaguardas en la Interfaz de Usuario y Cierre Automático
- **Ocultación Dinámica de Acciones:** Si un usuario carece de privilegios (ej. Operador o Auditor ante la destrucción de asientos), los controles visuales no se renderizan en la UI (`can_terminate`).
- **Detección de Pérdida Física y Auto-Cierre:** Si un archivo físico deja de existir en disco, el servicio `check_and_auto_close_if_file_missing()` detecta la inconsistencia, clausura formalmente el documento (`is_consumed=True`) y asienta una vicisitud inmutable en `DocumentAccessLog`.

### 4.4 Aislamiento a Nivel de Fila (Row-Level Security)
Las consultas en el Dashboard y la API filtran automáticamente los documentos accesibles según la pertenencia del usuario solicitante:
```python
if not user.is_superuser:
    user_uos = user.uo_memberships.values_list("organizational_unit_id", flat=True)
    qs = qs.filter(Q(origin_uo_id__in=user_uos) | Q(target_uo_id__in=user_uos) | Q(uploaded_by=user))
```

---

## 5. Tokens de Máquina (Zero-Knowledge M2M API Gate)

Para integraciones automatizadas (sistemas de RRHH, gestores documentales, ERPs), Arcamitte implementa tokens con el patrón de **Conocimiento Cero**:

1. **Generación Segura:**
   ```python
   raw_token = f"arca_live_{secrets.token_urlsafe(32)}"
   ```
2. **Almacenamiento Criptográfico:**
   El valor plano `raw_token` solo se muestra una única vez en la respuesta de creación. En base de datos únicamente se almacena su función resumen criptográfica SHA-256 (`hashed_token`).
3. **Autenticación en Tiempo Constante:**
   Al recibir una petición con el encabezado `X-API-Key: arca_live_...`, el microservicio calcula el SHA-256 del token provisto y realiza una búsqueda indexada. El token original nunca se encuentra en los registros del servidor ni en la base de datos.
4. **Control de Ámbitos (Scopes):**
   Cada token posee permisos granulares (`documents:read`, `documents:write`, `tokens:manage`).

---

## 6. Mitigación de Canales Laterales y Ataques de Temporización (CWE-208)

Si un atacante realiza peticiones concurrentes contra el endpoint de solicitud (`/arcamitte/solicitar/`) variando el hash SHA-256, podría deducir qué documentos existen midiendo diferencias de tiempo entre una respuesta fallida inmediata y una búsqueda exitosa que procesa destinatarios.

Para neutralizar este vector:
1. Cuando el hash no existe o el correo no coincide, el servicio ejecuta de forma síncrona una rutina sintética de PBKDF2:
   ```python
   hashlib.pbkdf2_hmac(
       "sha256",
       email.encode("utf-8"),
       file_hash.encode("utf-8"),
       iterations=TIMING_ATTACK_PBKDF2_ITERATIONS,  # 20,000 iteraciones
   )
   ```
2. La duración de la respuesta para hashes inexistentes es indistinguible de una solicitud legítima.
3. El mensaje devuelto es genérico en todos los casos:
   > *"Si los datos indicados corresponden a un documento disponible y una dirección de correo autorizada, recibirá en breve un código de verificación en su buzón."*

---

## 7. Registro de Auditoría Inmutable (WORM)

Cada interacción con un documento queda registrada en la tabla `DocumentAccessLog`:
- **Tipos de Evento:** `ACCESO_SOLICITADO`, `DESCARGA_COMPLETA`, `DESCARGA_AUDITORIA`, `INTENTO_FALLIDO`, `VICISITUD_FINALIZADO`, `EXPIRACION_AUTOMATICA`.
- **Inmutabilidad Absoluta:** El modelo `DocumentAccessLog` sobrescribe el método `delete()` en el ORM para impedir cualquier borrado programático o accidental:
  ```python
  def delete(self, *args, **kwargs):
      raise PermissionDenied("Los registros de auditoría son inmutables y de custodia legal.")
  ```
- **Preservación de Metadatos:** Se registra dirección IP del cliente, User-Agent, sello de tiempo UTC y correo del solicitante.
