# Modelo y Controles de Seguridad de Arcamitte

> 📖 **Guía Didáctica para Operadores y Administradores:**  
> Para una explicación pedagógica paso a paso orientada a usuarios no criptógrafos (explicación del Cifrado de Sobre, cómo funciona la rotación de claves maestras y el diccionario exhaustivo de directivas de `arcamitte.ini`), consulte el nuevo **[Manual de Ciberseguridad y Guía de Configuración para Operadores (docs/SECURITY_CONFIG_GUIDE.md)](SECURITY_CONFIG_GUIDE.md)**.

Este documento expone los controles técnicos de ciberseguridad implementados en **Arcamitte**, alineados con **ENS Categoría ALTA**, **NIST SP 800-53 Rev. 5**, **NIST SP 800-57 Part 1**, **NIST SP 800-63B**, **NIST SP 800-88 Rev. 1** y **OWASP API Security Top 10 (2023)**.

---

## 1. Mapeo de Mitigaciones OWASP API Security Top 10 (2023)

| Identificador OWASP | Vector de Riesgo | Controles Implementados en Arcamitte |
| :--- | :--- | :--- |
| **API1:2023 – Broken Object Level Authorization (BOLA)** | Acceso a documentos de otros departamentos mediante manipulación de identificadores. | • **Malla Departamental (UO Mesh):** Un usuario solo puede visualizar documentos cuya `origin_uo` o `target_uo` coincida con sus membresías activas.<br>• **Identificación Opaca:** El acceso público se referencia exclusivamente por el hash criptográfico SHA-256 del binario original, impidiendo la enumeración de IDs secuenciales. |
| **API2:2023 – Broken Authentication** | Compromiso de credenciales o suplantación de identidad en peticiones de API. | • **Tokens de Conocimiento Cero:** Las claves M2M (`arca_live_...`) se guardan únicamente como resumen SHA-256.<br>• **OTPs Efímeros:** Códigos de 6 dígitos generados mediante CSPRNG (`secrets`), con vida útil máxima de 15 minutos y bloqueo estricto tras 3 intentos fallidos.<br>• **Comparación en Tiempo Constante:** Validación de códigos con `secrets.compare_digest` para neutralizar ataques de canal lateral. |
| **API3:2023 – Broken Object Property Level Authorization** | Exposición o alteración indebida de atributos internos sensibles (DEK, flags). | • Los serializers de Django REST Framework aíslan los campos internos (`encrypted_dek`, `salt`, `internal_id`).<br>• El estado criptográfico público no expone listas de correos ni metadatos de custodia. |
| **API4:2023 – Unrestricted Resource Consumption** | Denegación de servicio por subida masiva de archivos o saturación de peticiones. | • **Límites de Tasa (Throttling):** Restricción de peticiones por IP en memoria caché (15 req/min para solicitudes, 30 req/min para canje).<br>• **Tamaño Máximo Estricto:** Validación de tamaño en streaming previa al procesamiento en memoria (por defecto 50 MB, configurable en `arcamitte.ini`). |
| **API5:2023 – Broken Function Level Authorization** | Usuarios con permisos básicos ejecutando acciones administrativas de auditoría. | • Segregación estricta de funciones entre rol `OPERADOR` (subida y gestión de su UO) y rol `AUDITOR` (descarga forense en memoria).<br>• Las descargas de auditoría requieren verificación concurrente en base de datos de la membresía del usuario antes de descifrar. |
| **API6:2023 – Unrestricted Access to Sensitive Business Flows** | Deducción de existencia de archivos mediante análisis de tiempos de respuesta (*Timing Attacks*). | • **Retardo Criptográfico Sintético:** Ante hashes inexistentes o correos no autorizados, el microservicio calcula síncronamente `hashlib.pbkdf2_hmac("sha256", ..., iterations=20000)` para equiparar la latencia con peticiones legítimas (CWE-208).<br>• **Respuestas Genéricas:** El sistema devuelve siempre el mismo mensaje indistinguible independientemente de si el documento existe o no. |
| **API7:2023 – Server Side Request Forgery (SSRF)** | Peticiones arbitrarias inducidas hacia servicios internos. | • El microservicio no realiza descargas ni peticiones HTTP salientes basadas en URLs provistas por el usuario.<br>• La comunicación saliente se limita al protocolo SMTP hacia servidores de correo autorizados. |
| **API8:2023 – Security Misconfiguration** | Claves criptográficas por defecto o entornos de producción mal configurados. | • **Validación en Arranque (`ArcamitteConfig.ready()`):** Si `DEBUG=False` y la clave `ARCAMITTE_FERNET_KEY` no es válida o mantiene el valor de plantilla (`cambiame...`), la aplicación bloquea el arranque arrojando `ImproperlyConfigured`. |
| **API9:2023 – Improper Inventory Management** | Exposición de endpoints obsoletos o de prueba. | • Enrutamiento unificado bajo espacios de nombres explícitos (`arcamitte:`, `dashboard:`, `api/v1/`).<br>• Purgado total de shims o rutas obsoletas. |
| **API10:2023 – Unsafe Consumption of APIs** | Confianza ciega en entradas de sistemas externos. | • Validación rigurosa de tipos y esquemas mediante formularios y serializers antes de interactuar con la capa criptográfica. |

---

## 2. Validación de Archivos en Profundidad (*Defense in Depth*)

Para neutralizar la subida de ejecutables camuflados (por ejemplo, renombrar `malware.exe` a `documento.pdf`), el validador `arcamitte/validators.py` ejecuta una inspección en tres niveles:

1. **Nivel 1 (Extensión):** Verifica que la extensión pertenezca a la lista blanca permitida (`.pdf`, `.docx`, `.odt`, `.xlsx`, `.jpg`, `.jpeg`, `.png`).
2. **Nivel 2 (MIME Type Declarado):** Comprueba el encabezado `Content-Type` enviado por el navegador o cliente API.
3. **Nivel 3 (Firma Binaria Real - Magic Bytes):** Lee los primeros 2.048 bytes del binario y consulta la base de firmas mágicas (`python-magic / libmagic`) para verificar la naturaleza real del contenido:
   - Los archivos ejecutables ELF, PE (Windows EXE/DLL), scripts Bash o ejecutables Mach-O son rechazados de inmediato arrojando una excepción de validación.

---

## 3. Sanitización Física de Medios (NIST SP 800-88 Rev. 1)

El borrado de un archivo en la mayoría de los sistemas operativos modernos únicamente desvincula el puntero del inodo, dejando los sectores físicos del disco accesibles para recuperación forense.

Arcamitte neutraliza este riesgo mediante el procedimiento `shred_and_delete_file`:
1. Identifica el tamaño exacto del archivo cifrado.
2. Abre el descriptor en modo binario directo y escribe un bloque de bytes pseudoaleatorios criptográficos obtenidos de `/dev/urandom` (`os.urandom`).
3. Invoca `f.flush()` y `os.fsync()` forzando a la controladora de disco a escribir los nuevos sectores físicos.
4. Ejecuta `path.unlink()` desvinculando el inodo.

---

## 4. Recomendaciones de Despliegue en Producción

Para entornos corporativos de producción:
1. **Terminación TLS:** Desplegar detrás de un proxy inverso (Nginx, Envoy o Caddy) con TLS 1.3 forzado y conjuntos de cifrado seguros (*Forward Secrecy*).
2. **Servidor WSGI/ASGI:** Ejecutar Django bajo Gunicorn o Uvicorn con usuarios sin privilegios (`nobody` o usuario de servicio dedicado `arcamitte`).
3. **Almacenamiento Cifrado:** Montar el directorio de archivos cifrados (`media/`) en un volumen con cifrado de disco completo (LUKS / BitLocker).
4. **Custodia de Claves:** Suministrar la variable `ARCAMITTE_FERNET_KEY` mediante inyección en tiempo de ejecución desde un gestor de secretos (HashiCorp Vault, AWS Secrets Manager o GCP Secret Manager).
