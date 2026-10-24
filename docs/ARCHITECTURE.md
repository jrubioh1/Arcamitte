# Arquitectura del Sistema Arcamitte

Este documento detalla la arquitectura técnica, los componentes internos, el flujo criptográfico de Cifrado de Sobre (*Envelope Encryption*), el aislamiento de malla departamental (*UO Mesh*), la política de borrado seguro (*Burn-After-Read / Sanitización NIST SP 800-88*) y el subsistema de auditoría inmutable de **Arcamitte**.

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

### 4.2 Roles y Privilegios en la UO
Los usuarios se asocian a las UOs mediante la entidad `UserUOMembership`:
- **Operador (`OPERADOR`):** Facultado para subir documentos, consultar estados y gestionar destinatarios de su departamento.
- **Auditor (`AUDITOR`):** Facultado para descargar copias de auditoría descifradas en memoria (siempre que pertenezca a la UO Emisora o UO Receptora) generando un registro formal de trazabilidad forense.

### 4.3 Aislamiento a Nivel de Fila (Row-Level Security)
Las consultas en el Dashboard y la API filtran automáticamente los documentos accesibles según la pertenencia del usuario solicitante:
```python
if not user.is_superuser:
    user_uos = user.uo_memberships.values_list("organizational_unit_id", flat=True)
    qs = qs.filter(Q(origin_uo_id__in=user_uos) | Q(target_uo_id__in=user_uos))
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
