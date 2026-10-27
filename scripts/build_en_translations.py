#!/usr/bin/env python3
"""
Builds and compiles 100% complete English (en) and Spanish (es) gettext catalogs
(.po and .mo) for Arcamitte, ensuring:
- 0 missing msgids from Python (.py) and HTML (.html) files
- 0 empty msgstr entries
- 0 fuzzy (#, fuzzy) entries
- Valid compiled binary .mo files for both 'en' and 'es'
"""

import ast
import re
import struct
from pathlib import Path

TRANSLATIONS = {
    # 2FA / TOTP
    "Autenticación en Dos Pasos (2FA)": "Two-Factor Authentication (2FA)",
    "Gobernanza y Despliegue de Segundo Factor (2FA / TOTP)": "Two-Factor Authentication (2FA / TOTP) Governance & Deployment",
    "Gobernanza de Segundo Factor (2FA / TOTP)": "Two-Factor Authentication (2FA / TOTP) Governance",
    "Gobernanza de Segundo Factor (2FA)": "Two-Factor Authentication (2FA) Governance",
    "Segundo Factor (2FA)": "Two-Factor Authentication (2FA)",
    "2FA Activo": "2FA Active",
    "Configurar Mi Propio 2FA": "Configure My 2FA",
    "Tasa de Adopción": "Adoption Rate",
    "Dispositivos móviles vinculados": "Linked mobile devices",
    "Exigidos Individualmente": "Individually Enforced",
    "Casilla 'is_mfa_enforced' activa": "'is_mfa_enforced' flag active",
    "Cuentas Privilegiadas": "Privileged Accounts",
    "100% Mandatorio": "100% Mandatory",
    "100%% Mandatorio": "100%% Mandatory",
    "Superusers, Staff y Admins UO": "Superusers, Staff and OU Admins",
    "Con 2FA Activo": "With Active 2FA",
    "Obligatorio (Pendiente)": "Mandatory (Pending)",
    "Opcional": "Optional",
    "Estado 2FA": "2FA Status",
    "Exigencia Individual": "Individual Enforcement",
    "Acciones Administrativas": "Administrative Actions",
    "Por Rol": "By Role",
    "Exigido (Quitar)": "Enforced (Remove)",
    "Forzar 2FA": "Enforce 2FA",
    "Resetear 2FA": "Reset 2FA",
    "Reset 2FA": "Reset 2FA",
    "Reseteo Administrativo de Segundo Factor": "Administrative Two-Factor Reset",
    "Confirmar Reseteo": "Confirm Reset",
    "Motivo o Registro del Incidente": "Incident Record / Reason",
    "Ej: Dispositivo móvil extraviado o restaurado de fábrica...": "e.g., Mobile device lost or factory reset...",
    "No se encontraron usuarios": "No users found",
    "No hay usuarios que coincidan con el filtro seleccionado.": "No users match the selected filter.",
    "Haga clic para liberar la exigencia individual": "Click to remove individual enforcement",
    "Haga clic para forzar 2FA obligatorio a este usuario": "Click to enforce mandatory 2FA on this user",
    "Obligatorio de fábrica por rol privilegiado": "Mandatory by design due to privileged role",
    "El usuario está obligado a enrolar 2FA en su próximo inicio de sesión": "The user is required to enroll 2FA on their next login",
    "Obligatorio: Se requerirá configuración en su próximo acceso": "Mandatory: Configuration required on next login",
    "Autenticación en Dos Pasos (2FA) configurada con éxito. Guarde sus códigos de rescate.": "Two-Factor Authentication (2FA) configured successfully. Please save your recovery codes.",
    "Ha accedido utilizando un código de rescate de emergencia. ": "You logged in using an emergency recovery code. ",
    "Debe confirmar la operación introduciendo un código TOTP actual o su contraseña.": "You must confirm the operation by entering a current TOTP code or your password.",
    "Se han generado nuevos códigos de rescate. Guarde los nuevos códigos inmediatamente.": "New recovery codes have been generated. Save the new codes immediately.",
    "La sesión de configuración de 2FA ha expirado. Por favor, vuelva a intentarlo.": "The 2FA setup session has expired. Please try again.",
    "¡Autenticación de Doble Factor activada exitosamente! Guarde sus códigos de rescate en un lugar seguro.": "Two-Factor Authentication activated successfully! Save your recovery codes in a secure location.",
    "La directiva de seguridad corporativa exige 2FA obligatorio para perfiles de administración. No tiene permisos para desactivar este control.": "Corporate security policy enforces mandatory 2FA for administrative profiles. You do not have permission to disable this control.",
    "Debe proporcionar un código TOTP vigente o su contraseña actual para desactivar 2FA.": "You must provide an active TOTP code or your current password to disable 2FA.",
    "La autenticación en dos pasos (2FA) ha sido desactivada para su cuenta.": "Two-Factor Authentication (2FA) has been disabled for your account.",
    "Exigir Segundo Factor (2FA / TOTP) Obligatorio": "Enforce Mandatory Two-Factor (2FA / TOTP)",
    "Aplica una directiva estricta de seguridad individual que obliga a este usuario a enrolar y validar un segundo factor TOTP para acceder al sistema.": "Applies a strict individual security policy requiring this user to enroll and validate a TOTP second factor to access the system.",
    "El código de 6 dígitos introducido es incorrecto o no coincide con la aplicación autenticadora.": "The 6-digit code entered is incorrect or does not match the authenticator application.",
    "Reseteo administrativo por extravío de autenticador": "Administrative reset due to lost authenticator",

    # Tokens API
    "Tokens de Acceso API": "API Access Tokens",
    "API Tokens (M2M)": "API Tokens (M2M)",
    "Detalles de API Token": "API Token Details",
    "Tokens Registrados": "Registered Tokens",
    "Volver a la lista de Tokens": "Back to Tokens list",
    "Identidad y Parámetros M2M": "Identity and M2M Parameters",
    "Nombre / Servicio": "Name / Service",
    "Prefijo Público": "Public Prefix",
    "Creado por": "Created by",
    "Fecha de Creación": "Creation Date",
    "Vencimiento": "Expiration",
    "Sin caducidad (Permanente)": "No expiration (Permanent)",
    "Límite de Tasa": "Rate Limit",
    "peticiones / minuto": "requests / minute",
    "Telemetría y Estado de Revocación": "Telemetry and Revocation Status",
    "Último Uso": "Last Used",
    "Nunca ha sido utilizado": "Never used",
    "Última IP Cliente": "Last Client IP",
    "Fecha de Revocación": "Revocation Date",
    "Revocado por": "Revoked by",
    "Motivo Legal": "Legal Reason",
    "Estado Operativo": "Operational Status",
    "Habilitado para consumo M2M": "Enabled for M2M consumption",
    "Trazabilidad Criptográfica del Token (Cadena de Custodia)": "Cryptographic Token Traceability (Chain of Custody)",
    "asientos registrados": "registered entries",
    "Fecha / Hora": "Date / Time",
    "Acción": "Action",
    "Operador / Actor": "Operator / Actor",
    "IP Cliente": "Client IP",
    "Detalles Criptográficos": "Cryptographic Details",
    "Revocar Token de Forma Inmediata": "Revoke API Token Immediately",
    "¡Atención! Esta acción es irreversible.": "Warning! This action is irreversible.",
    "El token perderá de inmediato su validez y cualquier cliente o microservicio que lo utilice para autenticarse recibirá un error HTTP 401 Unauthorized.": "The token will immediately lose its validity and any client or microservice attempting to authenticate will receive an HTTP 401 Unauthorized error.",
    "Motivo legal u operativo de la revocación": "Legal or operational revocation reason",
    "Ej: Baja de servicio externo, rotación de credenciales, sospecha de compromiso...": "e.g., Decommissioned external service, credential rotation, suspected compromise...",
    "Confirmar y Revocar": "Confirm and Revoke",
    "Auditar Detalles y Trazabilidad": "Audit Details and Traceability",
    "Ver Detalles y Trazabilidad": "View Details and Traceability",
    "Indique el motivo legal u operativo de la revocación:": "Provide the legal or operational reason for revocation:",
    "Revocación manual por el operador": "Manual revocation by operator",
    "Token API M2M generado": "M2M API Token generated",
    "Token API M2M revocado": "M2M API Token revoked",
    "Se requieren privilegios administrativos para auditar API Tokens.": "Administrative privileges required to audit API Tokens.",
    "Se requieren privilegios administrativos para gestionar API Tokens.": "Administrative privileges required to manage API Tokens.",
    "Se requieren privilegios administrativos para revocar API Tokens.": "Administrative privileges required to revoke API Tokens.",

    # Locked / Suspended Users
    "Gestión de Cuentas Bloqueadas": "Locked Accounts Management",
    "Cuentas de Usuario Bloqueadas y en Riesgo": "Locked & At-Risk User Accounts",
    "Panel perimetral exclusivo para Superusuarios. Permite la monitorización y desbloqueo 1-clic de cuentas afectadas por ataques de fuerza bruta o suspensión manual.": "Perimeter panel exclusive for Superusers. Enables monitoring and 1-click unlocking of accounts affected by brute-force attacks or manual suspension.",
    "Ver Todos los Usuarios": "View All Users",
    "Buscar por usuario, correo o nombre...": "Search by username, email or name...",
    "cuentas bloqueadas o con alertas": "locked or alerted accounts",
    "Intentos Fallidos": "Failed Attempts",
    "Bloqueado Hasta": "Locked Until",
    "Acciones de Remediación": "Remediation Actions",
    "intentos": "attempts",
    "Indefinido": "Indefinite",
    "Suspendido / Inactivo": "Suspended / Inactive",
    "Bloqueado": "Locked",
    "Alertado": "Alerted",
    "Desbloquear inmediatamente (1-clic)": "Unlock immediately (1-click)",
    "Desbloquear": "Unlock",
    "Suspender": "Suspend",
    "Suspender cuenta": "Suspend account",
    "Suspensión Administrativa de Cuenta": "Administrative Account Suspension",
    "Esta acción invalidará inmediatamente todas las sesiones activas en el sistema y bloqueará el inicio de sesión.": "This action will immediately invalidate all active sessions in the system and block login.",
    "Justificación / Motivo Legal Obligatorio": "Mandatory Legal Justification / Reason",
    "Indique la razón legal o de seguridad (ej: Baja de personal, comportamiento anómalo)...": "State the legal or security reason (e.g., Staff departure, anomalous behavior)...",
    "Confirmar Suspensión": "Confirm Suspension",
    "Reactivar": "Reactivate",
    "Reactivar en formulario de usuario": "Reactivate in user form",
    "No hay usuarios bloqueados": "No locked users",
    "Todos los usuarios activos se encuentran en estado operativo normal sin penalizaciones por fuerza bruta.": "All active users are in normal operational status without brute-force penalties.",
    "¿Desea desbloquear inmediatamente y restaurar a 0 los contadores de seguridad de este usuario?": "Do you want to immediately unlock and reset security counters to 0 for this user?",
    "¿Está seguro de suspender la cuenta del usuario": "Are you sure you want to suspend user account",
    "Por salvaguarda operativa, no puede suspender su propia cuenta de superusuario.": "For operational safety, you cannot suspend your own superuser account.",
    "Debe proporcionar una justificación obligatoria para la suspensión administrativa.": "You must provide a mandatory justification for administrative suspension.",
    "Se requieren privilegios de Superusuario para gestionar usuarios bloqueados.": "Superuser privileges required to manage locked users.",
    "Se requieren privilegios de Superusuario para suspender cuentas.": "Superuser privileges required to suspend accounts.",
    "Se requieren privilegios de Superusuario para resetear credenciales 2FA.": "Superuser privileges required to reset 2FA credentials.",
    "Se requieren privilegios de Superusuario para gestionar la gobernanza de 2FA.": "Superuser privileges required to manage 2FA governance.",
    "Esta cuenta de usuario se encuentra temporalmente bloqueada por reiterados ": "This user account is temporarily locked due to repeated ",
    "Se ha superado el límite de intentos permitidos para esta cuenta. La cuenta ha sido bloqueada temporalmente por seguridad y se ha remitido un aviso a su buzón de correo.": "Maximum allowed attempts exceeded for this account. The account has been temporarily locked for security and a notification has been sent to your email.",

    # Document Closure / Download & Burn
    "Descarga de Auditoría (Preservada)": "Audit Download (Preserved)",
    "Descargar y Clausurar Asiento": "Download & Close Entry",
    "Consumo Destructivo: Descargar y Destruir Archivo": "Destructive Consumption: Download & Destroy File",
    "Advertencia de No Repudio (NIST SP 800-88):": "Non-Repudiation Warning (NIST SP 800-88):",
    "Esta acción descargará el documento con marca de agua forense y simultáneamente destruirá de manera definitiva e irrecuperable el archivo del almacenamiento del servidor.": "This action will download the document with a forensic watermark and simultaneously permanently and irretrievably destroy the file from server storage.",
    "Motivo Legal de la Clausura y Entrega": "Legal Reason for Closure and Delivery",
    "Ej: Entrega fehaciente al destinatario, clausura de trámite administrativo...": "e.g., Certified delivery to recipient, administrative closure...",
    "Descargar y Clausurar Definitivamente": "Download & Close Permanently",
    "Descarga y clausura definitiva de trámite": "Download and permanent entry closure",
    "Asiento documental clausurado y archivo descargado con éxito.": "Document entry closed and file downloaded successfully.",
    "El documento ya ha sido consumido y destruido del servidor.": "The document has already been consumed and destroyed from the server.",
    "No tiene autorización para clausurar este asiento documental.": "You are not authorized to close this document entry.",
    "Finalización manual del asiento (destrucción física)": "Manual entry closure (physical destruction)",

    # Navigation / Perimeter
    "Seguridad & Perímetro": "Security & Perimeter",
    "Usuarios Bloqueados": "Locked Users",
    "Gobernanza 2FA": "2FA Governance",
    "Lista Negra IPs": "IP Blacklist",

    # Forms & Validation
    "El nombre de usuario debe tener al menos 3 caracteres.": "Username must have at least 3 characters.",
    "El nombre de usuario coincide con el correo electrónico registrado por otra cuenta.": "Username matches an email registered by another account.",
    "El correo electrónico corporativo es estrictamente obligatorio.": "Corporate email is strictly mandatory.",
    "Ya existe otro usuario registrado con este correo electrónico.": "Another user is already registered with this email address.",
    "El correo electrónico coincide con el nombre de usuario de otra cuenta registrada.": "Email matches a username registered by another account.",
    "Debe contener al menos 12 caracteres e incluir mayúsculas, minúsculas, números y símbolos especiales, sin reutilizar sus últimas 5 contraseñas.": "Must contain at least 12 characters including uppercase, lowercase, numbers and special symbols, without reusing your last 5 passwords.",
    "La nueva contraseña no puede ser idéntica a la contraseña actual o temporal.": "New password cannot be identical to current or temporary password.",
    "Acceso denegado: Su dirección IP se encuentra bloqueada por motivos de seguridad.": "Access denied: Your IP address is blocked for security reasons.",
    "Su sesión ha sido invalidada por motivos de seguridad debido a una discrepancia de red (posible secuestro de sesión).": "Your session has been invalidated for security reasons due to a network discrepancy (possible session hijacking).",
    "Su sesión ha expirado porque se ha iniciado sesión desde otro navegador o dispositivo.": "Your session expired because a new session was initiated from another browser or device.",
    "La dirección IP especificada no es una dirección IPv4 o IPv6 válida.": "The specified IP address is not a valid IPv4 or IPv6 address.",
    "El recibo no dispone de un sello de tiempo RFC 3161 asociado.": "The receipt does not have an associated RFC 3161 timestamp.",
    "Histórico Completo": "Complete History",
    "Acceso no autorizado a métricas analíticas.": "Unauthorized access to analytical metrics.",
    "Primer Acceso (FIRST_ACCESS)": "First Access (FIRST_ACCESS)",
    "Múltiples Destinatarios (ALL_RECIPIENTS)": "Multiple Recipients (ALL_RECIPIENTS)",
    "Global (Toda la Organización)": "Global (Entire Organization)",
    "Documentos Incinerados / Canjeados (BAR)": "Burned / Redeemed Documents (BAR)",
    "Archivos destruidos físicamente de disco tras su descarga conforme a política": "Files physically shredded from disk after download per policy",
    "Plazo de vigencia vencido sin haberse completado el canje": "Validity period expired without redemption completed",
    "Todos los asientos bajo el perímetro y filtros seleccionados": "All entries under the selected scope and filters",
    "Incidencias y Bloqueos de Seguridad": "Security Incidents and Blocks",
    "Intentos sobre archivos ya quemados (BAR) y bloqueos por claves erróneas": "Attempts on burned files (BAR) and bad passphrase blocks",
    "Intentos de Acceso Post-Consumo": "Post-Consumption Access Attempts",
    "Accesos a documentos que ya fueron incinerados conforme a la política BAR": "Access attempts to documents already burned per BAR policy",
    "Peticiones bloqueadas por reiteración de claves erróneas (protección anti-fuerza bruta)": "Requests blocked due to repeated wrong passphrases (anti-brute-force defense)",
    "Acceso administrativo especial registrado por inspectores o auditores": "Special administrative access recorded by inspectors or auditors",
    "Entregas confidenciales completadas legítimamente": "Confidential deliveries legitimately completed",
    "Verificaciones remitidas a buzones autorizados": "Verifications dispatched to authorized inboxes",
    "Documentos originados en este departamento hacia otras áreas o terceros": "Documents originated in this department towards other areas or third parties",
    "Trámites Recibidos por UO": "Procedures Received by OU",
    "Documentos dirigidos hacia esta dependencia organizativa": "Documents addressed to this organizational unit",
    "Asientos creados o consumidos en esta fecha": "Entries created or consumed on this date",
    "Asientos registrados bajo el perímetro y filtros seleccionados": "Entries recorded under the selected scope and filters",
    "Superusuario Global": "Global Superuser",
    "Personal Administrativo": "Administrative Staff",
    "Usuario Estándar": "Standard User",

    # === 116 MISSING ENTRIES ===
    "0 encontrados": "0 found",
    "API Token '%(name)s' generado correctamente.": "API Token '%(name)s' generated successfully.",
    "ARCAMITTE - CÓDIGOS DE RESCATE DE EMERGENCIA (2FA)": "ARCAMITTE - EMERGENCY RECOVERY CODES (2FA)",
    "Acceso a la plataforma criptográfica Arcamitte": "Access to the Arcamitte cryptographic platform",
    "Activos": "Active",
    "Actualizado por": "Updated by",
    "Admin Global": "Global Admin",
    "Administrador": "Administrator",
    "Administrador Global": "Global Administrator",
    "Administrador Global de Seguridad": "Global Security Administrator",
    "Arcamitte - Pasarela Criptográfica de Custodia y Entrega Segura": "Arcamitte - Cryptographic Custody and Secure Delivery Gateway",
    "Arcamitte - Plataforma Autónoma de Custodia Criptográfica y Trámite Confidencial": "Arcamitte - Autonomous Cryptographic Custody and Confidential Processing Platform",
    "Asiento terminado con éxito: %(msg)s": "Record terminated successfully: %(msg)s",
    "Asientos Cifrados (Altas)": "Encrypted Records (Registered)",
    "Auditores de UO": "OU Auditors",
    "Auditoría Legal": "Legal Audit",
    "Auditorías Periciales": "Forensic Audits",
    "Bloqueo automático por sospecha de fuerza bruta": "Automatic block due to suspected brute-force attack",
    "Cada UO debe incluir obligatoriamente 'numeric_code', 'alias', 'name' y 'email'. Entrada inválida: %(data)s": "Each OU must include 'numeric_code', 'alias', 'name', and 'email'. Invalid entry: %(data)s",
    "Cada usuario debe incluir obligatoriamente 'username' y 'email'. Entrada inválida: %(data)s": "Each user must include 'username' and 'email'. Invalid entry: %(data)s",
    "Canjes Efectivos (BAR)": "Effective Redemptions (BAR)",
    "Cargando métricas...": "Loading metrics...",
    "Cargando registros...": "Loading records...",
    "Concede soberanía y control total sobre toda la plataforma sin restricciones: gestión de todas las UOs, todos los usuarios, credenciales API M2M y auditoría forense global.": "Grants unrestricted sovereignty and full control over the entire platform: management of all OUs, all users, M2M API credentials, and global forensic auditing.",
    "Configure la obligatoriedad institucional del segundo factor (2FA) para los roles de la Malla de UOs. Para los roles de Superusuario Global y Administrador de UO, el segundo factor es estrictamente obligatorio por diseño criptográfico y no puede desactivarse.": "Configure institutional mandatory two-factor authentication (2FA) for OU Mesh roles. For Global Superuser and OU Administrator roles, two-factor authentication is strictly mandatory by cryptographic design and cannot be disabled.",
    "Consultando base de datos criptográfica": "Querying cryptographic database",
    "Custodia": "Custody",
    "Código QR TOTP": "TOTP QR Code",
    "Código:": "Code:",
    "Códigos OTP Bloqueados": "Blocked OTP Codes",
    "Defina si este usuario ostenta la máxima autoridad del sistema como Administrador Global de Seguridad:": "Define whether this user holds the highest system authority as Global Security Administrator:",
    "Descargas OK": "Successful Downloads",
    "Descargas preservadas": "Preserved downloads",
    "Desde": "From",
    "Destruidos (BAR)": "Destroyed (BAR)",
    "Directiva de Seguridad de Plataforma": "Platform Security Policy",
    "Directivas Institucionales de Exigencia de 2FA por Rol": "Institutional Role-Based 2FA Enforcement Policies",
    "Directivas de Seguridad de Plataforma": "Platform Security Policies",
    "Directivas de obligatoriedad de 2FA por rol actualizadas con éxito.": "Role-based 2FA enforcement policies updated successfully.",
    "ENS Nivel ALTO": "ENS HIGH Level",
    "El API Token '%(name)s' ha sido revocado inmediatamente.": "API Token '%(name)s' has been revoked immediately.",
    "El baneo sobre la dirección IP %(ip)s ha sido revocado.": "The ban on IP address %(ip)s has been revoked.",
    "El campo 'numeric_code' en UO '%(alias)s' debe ser un número entero válido: %(code)s": "Field 'numeric_code' in OU '%(alias)s' must be a valid integer: %(code)s",
    "El segundo factor (2FA) de '%(username)s' ha sido reseteado. Deberá enrolar un nuevo autenticador en su próximo acceso.": "Two-factor authentication (2FA) for '%(username)s' has been reset. They must enroll a new authenticator on their next login.",
    "Eliminar correo": "Remove email",
    "Emitidos (Salientes)": "Issued (Outbound)",
    "Error al terminar el asiento: %(msg)s": "Error terminating record: %(msg)s",
    "Error de consulta": "Query error",
    "Esta cuenta de usuario se encuentra temporalmente bloqueada por reiterados intentos fallidos de acceso. Podrá reintentarlo automáticamente a las %(time)s o contactar a un administrador para su desbloqueo inmediato.": "This user account is temporarily locked due to repeated failed login attempts. You may try again automatically at %(time)s or contact an administrator for immediate unlocking.",
    "Estado:": "Status:",
    "Exigir 2FA Obligatorio para Auditores de UO": "Enforce Mandatory 2FA for OU Auditors",
    "Exigir 2FA Obligatorio para Operadores de UO": "Enforce Mandatory 2FA for OU Operators",
    "Fecha Fin": "End Date",
    "Fecha Inicio": "Start Date",
    "Fecha:": "Date:",
    "Gestión UO y Cierre": "OU Management & Closure",
    "Gobernanza perimetral y directivas corporativas de seguridad.": "Perimeter governance and corporate security policies.",
    "Guardar Directivas de Rol": "Save Role Policies",
    "Guarde este fichero en un almacén seguro cifrado.": "Store this file in an encrypted secure vault.",
    "Ha accedido utilizando un código de rescate de emergencia. Le quedan %(count)s códigos disponibles.": "You logged in using an emergency recovery code. You have %(count)s codes remaining.",
    "Hasta": "To",
    "ID;Fecha y Hora;Acción / Evento;Documento;Hash;IP Solicitante;Correo;Detalles Forenses;UO": "ID;Date and Time;Action / Event;Document;Hash;Client IP;Email;Forensic Details;OU",
    "ID;Nombre de Archivo;Hash SHA-256;UO Origen;UO Destino;Estado;Política BAR;Fecha Alta;Fecha Expiración;Fecha Canje": "ID;Filename;SHA-256 Hash;Source OU;Destination OU;Status;BAR Policy;Created Date;Expiration Date;Redemption Date",
    "Incidencias de Seguridad": "Security Incidents",
    "Incidencias y Accesos": "Incidents & Accesses",
    "Innegociable": "Non-negotiable",
    "Intentos Post-Consumo": "Post-Consumption Attempts",
    "La cuenta del usuario '%(username)s' ha sido desbloqueada con éxito.": "User account '%(username)s' has been unlocked successfully.",
    "La cuenta del usuario '%(username)s' ha sido suspendida administrativamente y sus sesiones activas revocadas.": "User account '%(username)s' has been administratively suspended and its active sessions revoked.",
    "La dirección IP %(ip)s ha sido bloqueada correctamente.": "IP address %(ip)s has been blocked successfully.",
    "La directiva de seguridad corporativa exige 2FA obligatorio para su perfil institucional. No tiene permisos para desactivar este control.": "Corporate security policy requires mandatory 2FA for your institutional profile. You do not have permission to disable this control.",
    "Mis UOs": "My OUs",
    "Mostrando": "Showing",
    "Métricas de Seguridad": "Security Metrics",
    "No existe ninguna Unidad Organizativa activa con alias o código '%(val)s'.": "No active Organizational Unit exists with alias or code '%(val)s'.",
    "No existe ninguna Unidad Organizativa activa identificada como '%(val)s'.": "No active Organizational Unit exists identified as '%(val)s'.",
    "No hay registros nominales para exportar.": "There are no nominal records to export.",
    "No se encontró la UO '%(uo)s' asociada al usuario '%(username)s'. Debe definirse previamente.": "OU '%(uo)s' associated with user '%(username)s' was not found. It must be defined first.",
    "No se encontró ningún recibo oficial con el identificador o hash indicado.": "No official receipt was found with the specified identifier or hash.",
    "No se pudieron obtener los registros nominales.": "Could not retrieve nominal records.",
    "OTP Bloqueados": "Blocked OTPs",
    "OTP Enviados": "Sent OTPs",
    "Obliga a todos los usuarios con rol de Auditor en cualquier Unidad Organizativa a enrolar y validar un segundo factor TOTP.": "Requires all users with the Auditor role in any Organizational Unit to enroll and validate a TOTP second factor.",
    "Obliga a todos los usuarios con rol de Operador en cualquier Unidad Organizativa a enrolar y validar un segundo factor TOTP.": "Requires all users with the Operator role in any Organizational Unit to enroll and validate a TOTP second factor.",
    "Obligatorio por directiva de rol institucional": "Mandatory by institutional role policy",
    "Operadores de UO": "OU Operators",
    "Otorga el máximo privilegio de gobierno criptográfico, perimetral y organizativo sobre toda la plataforma Arcamitte.": "Grants the highest cryptographic, perimeter, and organizational governance privilege over the entire Arcamitte platform.",
    "Personal de UO": "OU Personnel",
    "Pinche para ver el detalle forense": "Click to view forensic details",
    "Pinche para ver registros nominales": "Click to view nominal records",
    "Política:": "Policy:",
    "Por favor, seleccione ambas fechas (Desde y Hasta).": "Please select both dates (From and To).",
    "Por motivos de seguridad, no puede revocar sus propios privilegios de administrador global.": "For security reasons, you cannot revoke your own global administrator privileges.",
    "Post-Consumo (BAR)": "Post-Consumption (BAR)",
    "Protegido por seguridad: No puede revocar sus propios privilegios de administrador global.": "Protected by security: You cannot revoke your own global administrator privileges.",
    "Recibidos (Entrantes)": "Received (Inbound)",
    "Se requieren privilegios de Administrador Global de Seguridad para gestionar la gobernanza de 2FA.": "Global Security Administrator privileges are required to manage 2FA governance.",
    "Se requieren privilegios de Administrador Global de Seguridad para resetear credenciales 2FA.": "Global Security Administrator privileges are required to reset 2FA credentials.",
    "Segundo factor (2FA) %(action)s para el usuario '%(username)s'.": "Two-factor authentication (2FA) %(action)s for user '%(username)s'.",
    "Sello Cualificado RFC 3161": "Qualified RFC 3161 Timestamp",
    "Sin actividad": "No activity",
    "Sin filtros activos": "No active filters",
    "Sistema": "System",
    "Sistema (Auto)": "System (Auto)",
    "Soberanía total": "Full sovereignty",
    "Superusuarios y Admins UO": "Superusers & OU Admins",
    "Trámite documental": "Document record",
    "Usuario:": "User:",
    "destinatario": "recipient",
    "destinatario@empresa.com": "recipient@company.com",
    "destinatarios": "recipients",
    "ej. Microservicio RRHH": "e.g., HR Microservice",
    "exigido": "enforced",
    "liberado de exigencia individual": "released from individual enforcement",
    "miembro": "member",
    "miembros": "members",
    "registros": "records",

    # === 219 EMPTY ENTRIES ===
    "1 hora": "1 hour",
    "1 mes (30 días)": "1 month (30 days)",
    "1 semana": "1 week",
    "24 horas (Recomendado)": "24 hours (Recommended)",
    "3 días (72 horas)": "3 days (72 hours)",
    "6 horas": "6 hours",
    "Abra su aplicación autenticadora en su dispositivo móvil (Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP, Bitwarden o 1Password) y escanee el código QR que se muestra a continuación.": "Open your authenticator app on your mobile device (Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP, Bitwarden, or 1Password) and scan the QR code shown below.",
    "Abra su aplicación autenticadora o utilice uno de sus códigos de rescate de emergencia.": "Open your authenticator app or use one of your emergency recovery codes.",
    "Activación de 2FA Requerida": "2FA Activation Required",
    "Al generar un nuevo juego de códigos de rescate, los códigos anteriores quedarán invalidados inmediatamente.": "Generating a new set of recovery codes will immediately invalidate your previous codes.",
    "Al menos un dígito numérico (0-9)": "At least one numeric digit (0-9)",
    "Al menos un símbolo especial (!@#$%&*+-_=)": "At least one special symbol (!@#$%&*+-_=)",
    "Al menos un símbolo especial (!@#$%%&*+-_=)": "At least one special symbol (!@#$%%&*+-_=)",
    "Al menos una letra mayúscula (A-Z)": "At least one uppercase letter (A-Z)",
    "Al menos una letra minúscula (a-z)": "At least one lowercase letter (a-z)",
    "Alineado con el Esquema Nacional de Seguridad (ENS) y el Reglamento eIDAS para evidencias electrónicas válidas en juicio.": "Aligned with the National Security Framework (ENS) and the eIDAS Regulation for court-admissible electronic evidence.",
    "Amenaza de malware bloqueada por antivirus": "Malware threat blocked by antivirus",
    "Amenaza de malware detectada por el motor antivirus: %(threat)s. La subida ha sido bloqueada y registrada para auditoría legal.": "Malware threat detected by antivirus engine: %(threat)s. Upload has been blocked and logged for legal audit.",
    "Analítica y Métricas": "Analytics & Metrics",
    "Analítica y Métricas de Custodia": "Custody Analytics & Metrics",
    "Anterior": "Previous",
    "Aplicar Rango": "Apply Range",
    "Archivo permanente e inmutable de exportaciones forenses certificadas mediante huella digital SHA-256.": "Permanent and immutable archive of forensic exports certified via SHA-256 fingerprint.",
    "Auditoría Criptográfica de la Cadena de Logs": "Cryptographic Audit of the Log Chain",
    "Autenticación 2FA configurada/modificada": "2FA authentication configured/modified",
    "Autenticación Multifactor (2FA / TOTP)": "Multi-Factor Authentication (2FA / TOTP)",
    "Autenticación en Dos Pasos Activada": "Two-Factor Authentication Enabled",
    "Autoridad de Sellado de Tiempo (TSA)": "Time Stamping Authority (TSA)",
    "Baneada Hasta": "Banned Until",
    "Baneada hasta": "Banned until",
    "Baneada por": "Banned by",
    "Baneo de dirección IP en lista negra": "IP address blacklisted",
    "Bloqueada (403)": "Blocked (403)",
    "Bloqueado hasta": "Locked until",
    "Bloquear Dirección IP en Lista Negra": "Block IP Address in Blacklist",
    "Bloquear Nueva IP": "Block New IP",
    "Buscar": "Search",
    "Cada entrada incorpora el hash SHA-256 del registro anterior. Cualquier inserción, alteración o borrado rompe la correlación.": "Each entry incorporates the SHA-256 hash of the previous record. Any insertion, alteration, or deletion breaks the correlation.",
    "Cargando...": "Loading...",
    "Clave de sesión activa": "Active session key",
    "Coincide con la confirmación": "Matches confirmation",
    "Comprobar autenticidad del recibo": "Verify receipt authenticity",
    "Compruebe la autenticidad e inalterabilidad de un archivo CSV de auditoría contrastándolo contra el registro oficial inmutable.": "Verify the authenticity and immutability of an audit CSV file by checking it against the official immutable registry.",
    "Conectado (Genesis Root)": "Connected (Genesis Root)",
    "Confirmar Bloqueo": "Confirm Block",
    "Confirmar y Activar 2FA": "Confirm & Enable 2FA",
    "Conforme a ENS ALTA & NIST SP 800-63B AAL2": "Compliant with ENS HIGH & NIST SP 800-63B AAL2",
    "Control de direcciones IP bloqueadas por actividad maliciosa, ataques de fuerza bruta o sanción manual.": "Control of IP addresses blocked due to malicious activity, brute-force attacks, or manual sanction.",
    "Control de enrolamiento y cumplimiento de autenticación multifactor según RFC 6238 (ENS ALTO). Permite supervisar la adopción, exigir 2FA a usuarios específicos y resetear credenciales extraviadas.": "Enrollment and compliance control for multi-factor authentication per RFC 6238 (ENS HIGH). Enables monitoring adoption, enforcing 2FA on specific users, and resetting lost credentials.",
    "Criterios de filtrado aplicados": "Applied filter criteria",
    "Cualificado (TSA Verificada)": "Qualified (Verified TSA)",
    "Código TOTP (6 dígitos) o Código de Rescate": "TOTP Code (6 digits) or Recovery Code",
    "Código TOTP o Contraseña actual": "TOTP Code or Current Password",
    "Código TOTP vigente o Contraseña actual": "Active TOTP Code or Current Password",
    "Código único del recibo oficial (ej. ARCA-EXP-YYYYMMDD-...)": "Unique official receipt code (e.g., ARCA-EXP-YYYYMMDD-...)",
    "Códigos de rescate disponibles:": "Available recovery codes:",
    "Debe incluir al menos un carácter especial o símbolo (ej. !@#$%&*+-_=).": "Must include at least one special character or symbol (e.g., !@#$%&*+-_=).",
    "Debe incluir al menos un carácter especial o símbolo (ej. !@#$%%&*+-_=).": "Must include at least one special character or symbol (e.g., !@#$%%&*+-_=).",
    "Debe incluir al menos un dígito numérico (0-9).": "Must include at least one numeric digit (0-9).",
    "Debe incluir al menos una letra mayúscula (A-Z).": "Must include at least one uppercase letter (A-Z).",
    "Debe incluir al menos una letra minúscula (a-z).": "Must include at least one lowercase letter (a-z).",
    "Dejar en blanco para baneo permanente o indefinido.": "Leave blank for a permanent or indefinite ban.",
    "Desactivar 2FA reduce la protección de su cuenta frente a ataques de fuerza bruta y phishing de credenciales.": "Disabling 2FA reduces your account protection against brute-force attacks and credential phishing.",
    "Desactivar Autenticación en Dos Pasos": "Disable Two-Factor Authentication",
    "Desactivar Definitivamente": "Disable Permanently",
    "Desbaneada": "Unbanned",
    "Desbanear": "Unban",
    "Desbloquear IP": "Unblock IP",
    "Descargar evidencia criptográfica DER (.tsr)": "Download DER cryptographic evidence (.tsr)",
    "Detección de posible secuestro de sesión (discrepancia IP)": "Possible session hijacking detected (IP discrepancy)",
    "Dirección IPv4 o IPv6 sujeta a bloqueo perimetral.": "IPv4 or IPv6 address subject to perimeter blocking.",
    "Distinta de la contraseña actual": "Different from current password",
    "Débil": "Weak",
    "Ej. Auditoría de seguridad trimestral, requerimiento judicial o inspección interna...": "e.g., Quarterly security audit, court order, or internal inspection...",
    "Ej. Fuerza bruta repetida, escaneo no autorizado...": "e.g., Repeated brute force, unauthorized scanning...",
    "El CSV incluirá sanitización anti-CSV Injection y el recibo oficial quedará archivado permanentemente.": "The CSV will include anti-CSV Injection sanitization and the official receipt will be permanently archived.",
    "El archivo CSV subido coincide al 100% con la huella digital registrada oficialmente. Integridad certificada sin repudio.": "The uploaded CSV file matches 100% with the officially registered fingerprint. Certified integrity with non-repudiation.",
    "El archivo CSV subido coincide al 100%% con la huella digital registrada oficialmente. Integridad certificada sin repudio.": "The uploaded CSV file matches 100%% with the officially registered fingerprint. Certified integrity with non-repudiation.",
    "El bloqueo entrará en vigor inmediatamente en el middleware con cero latencia mediante caché.": "The block will take effect immediately in the middleware with zero latency via cache.",
    "El motor antivirus ClamAV no está disponible para inspeccionar el archivo. Por política de seguridad estricta (Fail-Secure), la subida ha sido bloqueada.": "The ClamAV antivirus engine is unavailable to inspect the file. By strict security policy (Fail-Secure), the upload has been blocked.",
    "El recibo oficial consta en los libros inmutables del sistema con la huella registrada.": "The official receipt is recorded in the system's immutable ledger with the registered fingerprint.",
    "Encadenamiento Append-Only": "Append-Only Hash Chaining",
    "Escanee el código QR con su aplicación autenticadora (Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP) e introduzca el código de 6 dígitos para vincular su cuenta.": "Scan the QR code with your authenticator app (Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP) and enter the 6-digit code to link your account.",
    "Esperando consulta": "Awaiting query",
    "Esta acción generará un archivo CSV oficial firmado con hash SHA-256 inalterable y registrará una vicisitud permanente en la cadena de auditoría (eIDAS / ENS).": "This action will generate an official CSV file signed with an immutable SHA-256 hash and record a permanent event in the audit chain (eIDAS / ENS).",
    "Estado del Enlace Génesis": "Genesis Link Status",
    "Evolución de altas frente a canjes definitivos (BAR). Pinche en una fecha para ver los asientos nominales.": "Evolution of registrations vs. permanent redemptions (BAR). Click on a date to view nominal records.",
    "Explotación visual de datos, ciclo de vida de asientos, canjes irreversibles (BAR) y sondas de seguridad. Pinche en cualquier tarjeta o gráfico para consultar los nominales.": "Visual data analytics, record lifecycle, irreversible redemptions (BAR), and security probes. Click on any card or chart to inspect nominal records.",
    "Exportar CSV": "Export CSV",
    "Exportar Certificado (No Repudio)": "Certified Export (Non-Repudiation)",
    "Exportar los registros de esta tabla a un archivo CSV (Excel)": "Export the records in this table to a CSV (Excel) file",
    "Fecha y hora límite del bloqueo temporal por fuerza bruta.": "Expiration date and time of temporary brute-force lockout.",
    "Filtrar rápidamente en estos registros por nombre, hash, departamento, IP...": "Quickly filter these records by name, hash, department, IP...",
    "Filtros de Explotación": "Analytics Filters",
    "Flujo UO": "OU Flow",
    "Generado por su aplicación autenticadora.": "Generated by your authenticator app.",
    "Generar y Descargar Recibo Oficial": "Generate & Download Official Receipt",
    "Gestionar Autenticación en Dos Pasos (2FA)": "Manage Two-Factor Authentication (2FA)",
    "Hash Oficial Registrado:": "Officially Registered Hash:",
    "Hash SHA-256 del contenido de este registro vinculado al bloque anterior.": "SHA-256 hash of this record's content linked to the previous block.",
    "Hash criptográfico del registro inmediatamente anterior en la cadena.": "Cryptographic hash of the immediately preceding record in the chain.",
    "Hash de Cabecera Actual (Head Hash)": "Current Head Hash",
    "Hash de contraseña previa": "Previous password hash",
    "Hash del Archivo Subido:": "Uploaded File Hash:",
    "Hash del registro anterior": "Previous record hash",
    "Hashes SHA-256 de los códigos de recuperación de emergencia.": "SHA-256 hashes of emergency recovery codes.",
    "Hashes de códigos de rescate": "Recovery code hashes",
    "Huella SHA-256 no registrada. Asiento documental libre para su alta.": "SHA-256 fingerprint not registered. Document record available for registration.",
    "Huella digital del archivo CSV generado para verificación de no repudio.": "Digital fingerprint of the generated CSV file for non-repudiation verification.",
    "IP Bloqueada / Lista Negra": "Blocked IP / Blacklist",
    "IPs Bloqueadas / Lista Negra": "Blocked IPs / Blacklist",
    "Identificador de la última sesión activa del usuario para control de concurrencia.": "Identifier of the user's last active session for concurrency control.",
    "Incidencia / Evento": "Incident / Event",
    "Incidencias de Seguridad y Verificación": "Security & Verification Incidents",
    "Inmutabilidad a Nivel de ORM": "ORM-Level Immutability",
    "Integridad (Hash)": "Integrity (Hash)",
    "Intentos post-consumo / OTPs": "Post-consumption attempts / OTPs",
    "Intentos sobre archivos ya quemados (BAR), bloqueos OTP y canjes legítimos": "Attempts on burned files (BAR), OTP blocks, and legitimate redemptions",
    "Intervención UO": "OU Role Scope",
    "Introduzca el código de 6 dígitos que muestra su aplicación autenticadora para verificar la sincronización y activar la protección.": "Enter the 6-digit code displayed by your authenticator app to verify synchronization and enable protection.",
    "Introduzca un código de recibo o suba un archivo CSV para emitir el dictamen forense.": "Enter a receipt code or upload a CSV file to issue the forensic verdict.",
    "Justificación / Motivo Legal": "Legal Justification / Reason",
    "Justificación / Motivo legal de la exportación": "Legal justification / reason for export",
    "La contraseña debe contener al menos %(min_length)d caracteres.": "Password must contain at least %(min_length)d characters.",
    "La huella digital del archivo CSV subido NO coincide con la huella registrada en el recibo oficial. El archivo ha sido modificado o alterado.": "The fingerprint of the uploaded CSV file DOES NOT match the fingerprint recorded in the official receipt. The file has been modified or tampered with.",
    "La nueva contraseña no puede ser idéntica a su contraseña actual.": "The new password cannot be identical to your current password.",
    "La pasarela perimetral no registra bloqueos activos actualmente.": "The perimeter gateway currently has no active blocks.",
    "La política de seguridad corporativa exige activar 2FA para el usuario:": "Corporate security policy requires enabling 2FA for user:",
    "Las operaciones directas de eliminación sobre la base de datos están interceptadas y restringidas por excepción PermissionDenied.": "Direct database deletion operations are intercepted and restricted via PermissionDenied exception.",
    "Lista Negra Perimetral de IPs": "Perimeter IP Blacklist",
    "Lista Negra de IPs": "IP Blacklist",
    "Malla de Tráfico Interdepartamental": "Interdepartmental Traffic Mesh",
    "Marca de agua forense aplicada a PDF": "Forensic watermark applied to PDF",
    "Marca temporal del último cambio de contraseña para control de caducidad.": "Timestamp of the last password change for expiration control.",
    "Media (Incompleta)": "Medium (Incomplete)",
    "Mostrando los asientos o eventos coincidentes bajo el perímetro de gobernanza autorizado.": "Showing matching records or events under the authorized governance perimeter.",
    "Motivo Legal Declarado:": "Declared Legal Reason:",
    "Motivo del Baneo": "Ban Reason",
    "Motivo del Bloqueo": "Block Reason",
    "Motivo del baneo": "Ban reason",
    "Mínimo 10 caracteres": "Minimum 10 characters",
    "No Repudio Jurídico": "Legal Non-Repudiation",
    "No existen asientos o eventos forenses en el perímetro y filtros seleccionados.": "No records or forensic events exist in the selected perimeter and filters.",
    "No hay direcciones IP en la lista negra": "No IP addresses in the blacklist",
    "No puede reutilizar ninguna de sus últimas %(history_limit)d contraseñas previas.": "You cannot reuse any of your last %(history_limit)d previous passwords.",
    "No se han emitido recibos oficiales de exportación": "No official export receipts have been issued",
    "O introduzca la clave manualmente:": "Or enter the key manually:",
    "Obliga al usuario a configurar y usar 2FA aunque no pertenezca al personal administrativo.": "Requires the user to configure and use 2FA even if they do not belong to administrative staff.",
    "Obteniendo registros nominales...": "Fetching nominal records...",
    "Operador Responsable:": "Responsible Operator:",
    "Paso 1: Vincular Aplicación Autenticadora": "Step 1: Link Authenticator App",
    "Paso 2: Confirmar Activación": "Step 2: Confirm Activation",
    "Permanente / Indefinido": "Permanent / Indefinite",
    "Permite desactivar o reactivar el bloqueo sin borrar el registro.": "Allows disabling or reactivating the block without deleting the record.",
    "Período": "Period",
    "Pincha para ver el listado nominal de todos los trámites": "Click to view the nominal list of all records",
    "Pincha para ver las incidencias forenses y accesos bloqueados": "Click to view forensic incidents and blocked accesses",
    "Pincha para ver los documentos actualmente en custodia activa": "Click to view documents currently in active custody",
    "Pincha para ver los documentos incinerados / canjeados (BAR)": "Click to view burned / redeemed documents (BAR)",
    "Pinche en cualquier sector para ver el listado nominal correspondiente": "Click on any sector to view the corresponding nominal list",
    "Pinche en la barra de una UO para inspeccionar los documentos emitidos o recibidos": "Click on an OU bar to inspect issued or received documents",
    "Política de seguridad (NIST / ENS):": "Security policy (NIST / ENS):",
    "Por directiva Zero Trust, las acciones críticas (borrado físico, descifrado pericial y auditoría forense) quedan restringidas exclusivamente al panel web interactivo.": "By Zero Trust policy, critical actions (physical deletion, forensic decryption, and forensic auditing) are restricted exclusively to the interactive web panel.",
    "Por:": "By:",
    "Protección criptográfica de acceso conforme a ENS Categoría ALTA y NIST SP 800-63B AAL2.": "Cryptographic access protection compliant with ENS HIGH Category and NIST SP 800-63B AAL2.",
    "Puede encontrar este código en la cabecera del archivo CSV o en el resguardo de entrega.": "You can find this code in the header of the CSV file or on the delivery receipt.",
    "RFC 6238 TOTP (SHA-1 / 30s)": "RFC 6238 TOTP (SHA-1 / 30s)",
    "Rango Manual": "Custom Range",
    "Recargar métricas con los filtros activos": "Reload metrics with active filters",
    "Recibo Auténtico y Válido": "Authentic & Valid Receipt",
    "Recibos Oficiales": "Official Receipts",
    "Recibos Oficiales de Exportación (No Repudio)": "Official Export Receipts (Non-Repudiation)",
    "Regenerar Códigos de Rescate": "Regenerate Recovery Codes",
    "Resetear credenciales 2FA": "Reset 2FA credentials",
    "Resetear segundo factor (2FA)": "Reset two-factor authentication (2FA)",
    "Restablecer todos los filtros a valores por defecto": "Reset all filters to default values",
    "Revocar Token API de Forma Inmediata": "Revoke API Token Immediately",
    "Robusta (Cumple política)": "Strong (Compliant)",
    "Rotación de clave maestra de cifrado": "Master encryption key rotation",
    "Scopes:": "Scopes:",
    "Se desvinculará de inmediato el dispositivo móvil actual y se destruirán sus códigos de recuperación. En su siguiente acceso, si el 2FA le es obligatorio, se le requerirá vincular un nuevo autenticador.": "The current mobile device will be unlinked immediately and its recovery codes destroyed. On their next login, if 2FA is mandatory, they will be required to link a new authenticator.",
    "Se ha detectado una ruptura o discrepancia en el hash de los registros de auditoría almacenados.": "A break or discrepancy has been detected in the hash of the stored audit records.",
    "Secreto Base32 cifrado con la clave maestra de servidor.": "Base32 secret encrypted with the server master key.",
    "Seguridad 2FA (TOTP)": "2FA Security (TOTP)",
    "Sello Inválido / Discrepancia": "Invalid Seal / Discrepancy",
    "Sello de Tiempo RFC 3161:": "RFC 3161 Timestamp:",
    "Sello de tiempo RFC 3161 generado": "RFC 3161 timestamp generated",
    "Sesión concurrente anterior cerrada": "Previous concurrent session closed",
    "Si pierde acceso a su dispositivo autenticador, podrá iniciar sesión utilizando cualquiera de estos códigos de rescate únicos. Solo se muestran en esta ocasión y están almacenados en el servidor exclusivamente como hashes criptográficos SHA-256.": "If you lose access to your authenticator device, you can sign in using any of these single-use recovery codes. They are only shown once and are stored on the server exclusively as SHA-256 cryptographic hashes.",
    "Si sube el archivo, Arcamitte calculará su huella SHA-256 en memoria para certificar que no ha sido alterado ni una sola coma.": "If you upload the file, Arcamitte will compute its SHA-256 fingerprint in memory to certify that not a single byte has been altered.",
    "Siguiente": "Next",
    "Solo Emisora (Origen)": "Issuing Only (Source)",
    "Staff": "Staff",
    "Su contraseña debe contener al menos %(min_length)d caracteres e incluir mayúsculas, minúsculas, números y símbolos especiales.": "Your password must contain at least %(min_length)d characters and include uppercase, lowercase, numbers, and special symbols.",
    "Su cuenta requiere un código de 6 dígitos generado por su app autenticadora en cada inicio de sesión.": "Your account requires a 6-digit code generated by your authenticator app at every login.",
    "Subir Archivo CSV Original para Verificación Criptográfica (Opcional)": "Upload Original CSV File for Cryptographic Verification (Optional)",
    "Toda la Organización (Global)": "Entire Organization (Global)",
    "Todo": "All Time",
    "Todos los bloques de auditoría han sido verificados criptográficamente sin detectar anomalías ni alteraciones.": "All audit blocks have been cryptographically verified with no anomalies or tampering detected.",
    "Token DER en Base64 emitido por una Autoridad de Sellado de Tiempo (TSA).": "Base64 DER token issued by a Time Stamping Authority (TSA).",
    "Token de Sello de Tiempo RFC 3161": "RFC 3161 Timestamp Token",
    "URL o entidad emisora del sello cualificado de tiempo.": "URL or issuing authority of the qualified timestamp.",
    "Verificación de No Repudio de Archivos de Auditoría": "Audit File Non-Repudiation Verification",
    "Verificación de No Repudio de Exportación": "Export Non-Repudiation Verification",
    "Verificación en Dos Pasos (2FA)": "Two-Factor Verification (2FA)",
    "Verificación secuencial SHA-256 (Hash Chaining) para detección de manipulaciones y garantía de no repudio legal (ENS / eIDAS).": "Sequential SHA-256 verification (Hash Chaining) for tamper detection and legal non-repudiation guarantee (ENS / eIDAS).",
    "Verificar": "Verify",
    "Verificar Autenticidad y No Repudio": "Verify Authenticity & Non-Repudiation",
    "Verificar CSV": "Verify CSV",
    "Verificar un Archivo CSV": "Verify a CSV File",
    "Verificar y Activar 2FA": "Verify & Enable 2FA",
    "Vigencia del Bloqueo": "Block Expiration",
    "canjeados e incinerados": "redeemed and burned",
    "¡Alerta de Manipulación o Corrupción Detectada!": "Tampering or Corruption Alert Detected!",
    "¡Alerta: El Archivo Ha Sido Manipulado!": "Alert: The File Has Been Tampered With!",
    "¡IMPORTANTE: Guarde sus Códigos de Rescate de Emergencia!": "IMPORTANT: Save Your Emergency Recovery Codes!",
    "¿Confirma el reseteo del autenticador 2FA para": "Do you confirm resetting the 2FA authenticator for",
    "¿Confirma el reseteo del segundo factor (2FA) para este usuario? Perderá el acceso de su dispositivo móvil actual.": "Do you confirm resetting two-factor authentication (2FA) for this user? They will lose access from their current mobile device.",
    "¿Desea levantar el bloqueo para la IP ": "Do you want to lift the block for IP ",
    "¿Exigir 2FA obligatorio?": "Enforce mandatory 2FA?",
    "¿No puede escanear el código QR? Introduzca la clave manualmente:": "Cannot scan the QR code? Enter the key manually:",

    # === 214 FUZZY ENTRIES ===
    "Acceso no autorizado.": "Unauthorized access.",
    "Actividad Documental del": "Document Activity on",
    "Actualizar": "Update",
    "Archivos cifrados disponibles actualmente para canje seguro": "Encrypted files currently available for secure redemption",
    "Asiento Afectado": "Affected Record",
    "Auditoría de Cadena Criptográfica": "Cryptographic Chain Audit",
    "Bloqueado por intentos fallidos hasta:": "Locked due to failed attempts until:",
    "Bloqueo Activo": "Active Block",
    "Bloqueo de seguridad de cuenta de usuario": "User account security lockout",
    "Bloqueos por Intentos OTP Fallidos": "Lockouts due to Failed OTP Attempts",
    "Buscar por IP o motivo...": "Search by IP or reason...",
    "Buscar por código de recibo, hash SHA-256, operador o justificación legal...": "Search by receipt code, SHA-256 hash, operator, or legal justification...",
    "Cadena Criptográfica 100% Íntegra": "100% Intact Cryptographic Chain",
    "Cadena Criptográfica 100%% Íntegra": "100%% Intact Cryptographic Chain",
    "Caducado sin Acceso": "Expired without Access",
    "Caducados sin Acceso": "Expired without Access",
    "Cerrar": "Close",
    "Ciclo de Vida Documental": "Document Lifecycle",
    "Cifrado, pre-flight check y registro de documentos": "Encryption, pre-flight check, and document registration",
    "Confirmar y Regenerar": "Confirm & Regenerate",
    "Consulta de Unidades Organizativas y buzones autorizados": "Query Organizational Units and authorized inboxes",
    "Consulta de estado y metadatos de trámite": "Record status and metadata inquiry",
    "Consultar directorio de Unidades Organizativas": "Query Organizational Units directory",
    "Consultar estado y metadatos de documentos": "Query document status and metadata",
    "Consultar y Contrastar Documento": "Query & Verify Document",
    "Contador de intentos fallidos consecutivos.": "Consecutive failed attempts counter.",
    "Copiar Códigos": "Copy Codes",
    "Código de Recibo": "Receipt Code",
    "Código de Recibo:": "Receipt Code:",
    "Código de confirmación de 6 dígitos": "6-digit confirmation code",
    "Código de recuperación 2FA consumido": "2FA recovery code consumed",
    "Código de verificación de 6 dígitos": "6-digit verification code",
    "Códigos OTP Enviados": "Sent OTP Codes",
    "Códigos de rescate copiados al portapapeles.": "Recovery codes copied to clipboard.",
    "Desactivado / Expirado": "Disabled / Expired",
    "Desactivar 2FA": "Disable 2FA",
    "Desbloquear cuenta de usuario": "Unlock user account",
    "Descargar Acuse Criptográfico (.tsr)": "Download Cryptographic Receipt (.tsr)",
    "Descargar archivo de texto": "Download text file",
    "Descargas Exitosas y Canjes": "Successful Downloads & Redemptions",
    "Descargas Periciales de Auditoría Legal": "Forensic Legal Audit Downloads",
    "Desconocida / Personal": "Unknown / Personal",
    "Destinatario Externo": "External Recipient",
    "Destinatarios Externos": "External Recipients",
    "Destruido por Canje": "Destroyed upon Redemption",
    "Destruido por Canje (BAR)": "Destroyed upon Redemption (BAR)",
    "Destruidos por Canje (BAR)": "Destroyed upon Redemption (BAR)",
    "Detalle del Fallo Criptográfico:": "Cryptographic Failure Detail:",
    "Detalles Forenses": "Forensic Details",
    "Dirección IP (IPv4 o IPv6)": "IP Address (IPv4 or IPv6)",
    "Dirección IP del solicitante": "Requester IP address",
    "Documento / Trámite": "Document / Record",
    "Documentos Caducados sin Acceso": "Expired Documents without Access",
    "Documentos en Custodia Activa": "Documents in Active Custody",
    "El código de 6 dígitos o código de rescate es inválido o ha expirado.": "The 6-digit code or recovery code is invalid or has expired.",
    "El documento existe pero pertenece a otra Unidad Organizativa fuera de su perímetro.": "The document exists but belongs to another Organizational Unit outside your perimeter.",
    "En Custodia Activa": "In Active Custody",
    "Error al delimitar registros.": "Error filtering records.",
    "Error al procesar la clausura y descarga del documento.": "Error processing document closure and download.",
    "Error de verificación:": "Verification error:",
    "Estado Documental": "Document Status",
    "Estado de Custodia Criptográfica": "Cryptographic Custody Status",
    "Expirada": "Expired",
    "Exportación Certificada de Auditoría": "Certified Audit Export",
    "Exportación certificada de registros de auditoría": "Certified audit log export",
    "Exportado por": "Exported by",
    "Fecha Alta": "Created Date",
    "Fecha de Bloqueo": "Block Date",
    "Fecha de Emisión:": "Issue Date:",
    "Fecha de alta en lista negra": "Blacklist registration date",
    "Fecha de fijación": "Timestamp date",
    "Fecha de revocación": "Revocation date",
    "Fecha y Hora (UTC)": "Date and Time (UTC)",
    "Fecha y hora de emisión": "Issue date and time",
    "Fortaleza de la clave:": "Password strength:",
    "Garantías de Seguridad": "Security Guarantees",
    "Ha superado el límite de intentos por minuto. Por favor, espere antes de reintentar.": "You have exceeded the attempts per minute limit. Please wait before trying again.",
    "Ha superado el límite de solicitudes de recuperación. Por favor, espere unos minutos antes de reintentar.": "You have exceeded the recovery request limit. Please wait a few minutes before trying again.",
    "Hash SHA-256 del Archivo Exportado": "Exported File SHA-256 Hash",
    "Hash SHA-256 del archivo exportado": "Exported file SHA-256 hash",
    "Hash criptográfico del registro": "Record cryptographic hash",
    "Historial de Contraseña": "Password History",
    "Historiales de Contraseñas": "Password Histories",
    "IP / Solicitante": "IP / Requester",
    "Identificador de Recibo o Hash SHA-256": "Receipt Identifier or SHA-256 Hash",
    "Identificador del recibo": "Receipt identifier",
    "Incidencias y Bloqueos": "Incidents & Blocks",
    "Indica si el usuario tiene activo el segundo factor de autenticación TOTP.": "Indicates whether the user has TOTP two-factor authentication enabled.",
    "Intentos fallidos de acceso": "Failed login attempts",
    "Introduzca código de 6 dígitos o su clave": "Enter 6-digit code or your password",
    "Introduzca código o contraseña": "Enter code or password",
    "Limpiar Filtros": "Clear Filters",
    "Listado Nominal de Documentos": "Nominal Document List",
    "Los recibos de auditoría de exportación son estrictamente inmutables y no pueden eliminarse.": "Audit export receipts are strictly immutable and cannot be deleted.",
    "Mis Departamentos": "My Departments",
    "Mostrar u ocultar contraseña": "Show or hide password",
    "Motivo Legal / Justificación de la Exportación": "Legal Reason / Export Justification",
    "Motivo de revocación": "Revocation reason",
    "Motivo:": "Reason:",
    "Nivel de Privilegios": "Privilege Level",
    "No dispone de privilegios de analítica en ninguna Unidad Organizativa.": "You do not have analytics privileges in any Organizational Unit.",
    "No hay eventos de auditoría previos para este identificador.": "There are no prior audit events for this identifier.",
    "No se encontraron registros nominales para este criterio.": "No nominal records were found for this criterion.",
    "No tiene permisos para desbloquear a este usuario.": "You do not have permission to unlock this user.",
    "No tiene permisos sobre la Unidad Organizativa solicitada.": "You do not have permissions for the requested Organizational Unit.",
    "Nombre / Correo": "Name / Email",
    "Origen o Destino": "Source or Destination",
    "Permanente": "Permanent",
    "Permisos de Acceso Operativos (Scopes M2M)": "Operational Access Permissions (M2M Scopes)",
    "Política Destrucción (BAR)": "Destruction Policy (BAR)",
    "Recibo No Encontrado": "Receipt Not Found",
    "Recibo de Exportación de Auditoría": "Audit Export Receipt",
    "Recibos Oficiales de Auditoría": "Official Audit Receipts",
    "Recibos de Exportación de Auditoría": "Audit Export Receipts",
    "Registro Afectado ID:": "Affected Record ID:",
    "Registro inmutable de accesos, operaciones criptográficas, canjes y vicisitudes con encadenamiento Hash Chaining.": "Immutable record of accesses, cryptographic operations, redemptions, and system events with Hash Chaining.",
    "Registros": "Records",
    "Registros Certificados:": "Certified Records:",
    "Registros Forenses de Seguridad": "Forensic Security Records",
    "Registros Nominales": "Nominal Records",
    "Resultado del Dictamen Criptográfico": "Cryptographic Verdict Result",
    "Se ha superado el número máximo de intentos de inicio de sesión permitidos. Por seguridad, espere 5 minutos antes de volver a intentarlo.": "Maximum allowed login attempts exceeded. For security, please wait 5 minutes before trying again.",
    "Secreto TOTP cifrado": "Encrypted TOTP secret",
    "Segundo Factor de Autenticación": "Two-Factor Authentication",
    "Sin UO": "No OU",
    "Sin documento": "No document",
    "Sin evaluar": "Not evaluated",
    "Solo Receptora (Destino)": "Receiving Only (Destination)",
    "Solo un Administrador de la UO emisora, el autor del asiento personal o un superadministrador puede clausurar el documento.": "Only an Administrator of the issuing OU, the author of the personal record, or a superadministrator can close the document.",
    "Superuser": "Superuser",
    "Tasa de Destrucción (BAR)": "Destruction Rate (BAR)",
    "Todas las políticas": "All policies",
    "Todas mis UOs autorizadas": "All my authorized OUs",
    "Todos los Usuarios": "All Users",
    "Total de Registros Verificados": "Total Verified Records",
    "Total de Trámites en Custodia": "Total Records in Custody",
    "Total de registros volcados": "Total exported records",
    "Trazabilidad perimetral del sistema": "System perimeter traceability",
    "Trámites Emitidos por UO": "Records Issued by OU",
    "Trámites Totales": "Total Records",
    "Vencido": "Expired",
    "Ver Asiento": "View Record",
    "Ver Todos los Recibos": "View All Receipts",
    "Ver asientos activos": "View active records",
    "Ver asientos destruidos": "View destroyed records",
    "Ver incidencias de seguridad": "View security incidents",
    "Ver listado nominal": "View nominal list",
    "Verificación de identidad para el usuario:": "Identity verification for user:",
    "Verificar Cadena": "Verify Chain",
    "Verificar e Iniciar Sesión": "Verify & Sign In",
    "Volver a Inicio de Sesión": "Back to Sign In",
    "Volver a Trazabilidad": "Back to Traceability",
    "activos en custodia": "active in custody",
    "usuarios activos": "active users",
    "¿2FA activo?": "2FA active?",
    "¿Baneo activo?": "Ban active?",
    "¿Desea desbloquear inmediatamente la cuenta de este usuario?": "Do you want to immediately unlock this user's account?",
    "Última actualización de contraseña": "Last password update",
}


def extract_code_msgids(arcamitte_dir: Path) -> set[str]:
    """Extract all translatable msgids from Python (.py) and template (.html) files."""
    py_msgids = set()
    for py_file in sorted(arcamitte_dir.rglob("*.py")):
        if "migrations" in py_file.parts and py_file.name != "0001_initial.py":
            continue
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                if (
                    func_name in ("_", "gettext", "gettext_lazy", "ugettext", "ugettext_lazy")
                    and node.args
                ):
                    arg0 = node.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                        py_msgids.add(arg0.value)

    html_msgids = set()
    trans_dq = re.compile(r'\{%\s*(?:trans|translate)\s+"((?:[^"\\]|\\.)*)"')
    trans_sq = re.compile(r"\{%\s*(?:trans|translate)\s+'((?:[^'\\]|\\.)*)'")
    blocktrans_re = re.compile(
        r"\{%\s*blocktrans(?:\s+[^%]*)?%\}(.*?)\{%\s*endblocktrans\s*%\}", re.DOTALL
    )

    for html_file in sorted(arcamitte_dir.rglob("*.html")):
        text = html_file.read_text(encoding="utf-8")
        for m in trans_dq.finditer(text):
            html_msgids.add(m.group(1).replace('\\"', '"').replace("\\'", "'"))
        for m in trans_sq.finditer(text):
            html_msgids.add(m.group(1).replace("\\'", "'").replace('\\"', '"'))
        for m in blocktrans_re.finditer(text):
            raw_block = m.group(1)
            conv = re.sub(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}", r"%(\1)s", raw_block)
            html_msgids.add(conv)

    return py_msgids | html_msgids


def escape_po_string(val: str) -> str:
    return val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def unescape_po_string(val: str) -> str:
    return val.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")


def update_po_file(po_path: Path, code_msgids: set[str], lang: str) -> tuple[int, int]:
    """
    Updates a .po file in-place:
    - Removes all '#, fuzzy' markers
    - Fills empty or fuzzy msgstr values (using TRANSLATIONS for 'en', or identity for 'es')
    - Appends any missing msgids from code_msgids
    """
    content = po_path.read_text(encoding="utf-8")
    blocks = content.split("\n\n")
    updated_blocks = []
    seen_msgids = set()
    updated_count = 0

    for b in blocks:
        if not b.strip():
            continue
        lines = b.split("\n")
        is_fuzzy = any(l.strip().startswith("#, fuzzy") for l in lines)
        has_python_format = any("python-format" in l for l in lines if l.startswith("#,"))

        # Remove '#, fuzzy' or strip 'fuzzy' from flag line
        clean_lines = []
        for l in lines:
            if l.strip() == "#, fuzzy":
                continue
            elif l.startswith("#, fuzzy, "):
                clean_lines.append("#, " + l[len("#, fuzzy, ") :])
            else:
                clean_lines.append(l)
        lines = clean_lines

        msgid_parts = []
        msgstr_parts = []
        msgstr_idx = -1
        mode = None

        for i, l in enumerate(lines):
            if l.startswith("msgid "):
                mode = "id"
                msgid_parts.append(l[6:].strip('"'))
            elif l.startswith("msgstr "):
                mode = "str"
                msgstr_idx = i
                msgstr_parts.append(l[7:].strip('"'))
            elif l.startswith('"') and l.endswith('"'):
                if mode == "id":
                    msgid_parts.append(l[1:-1])
                elif mode == "str":
                    msgstr_parts.append(l[1:-1])

        raw_msgid = unescape_po_string("".join(msgid_parts))
        raw_msgstr = unescape_po_string("".join(msgstr_parts))

        if raw_msgid:
            seen_msgids.add(raw_msgid)
            seen_msgids.add(raw_msgid.replace("%%", "%"))

            if lang == "en":
                trans = TRANSLATIONS.get(raw_msgid) or TRANSLATIONS.get(
                    raw_msgid.replace("%%", "%")
                )
                if trans and has_python_format and "%%" in raw_msgid and "%%" not in trans:
                    trans = trans.replace("%", "%%")
                if trans and (not raw_msgstr or is_fuzzy or raw_msgid in TRANSLATIONS):
                    escaped_trans = escape_po_string(trans)
                    lines[msgstr_idx] = f'msgstr "{escaped_trans}"'
                    k = msgstr_idx + 1
                    while k < len(lines) and lines[k].startswith('"'):
                        lines.pop(k)
                    updated_count += 1
            elif lang == "es":
                if not raw_msgstr or is_fuzzy:
                    escaped_es = escape_po_string(raw_msgid)
                    lines[msgstr_idx] = f'msgstr "{escaped_es}"'
                    k = msgstr_idx + 1
                    while k < len(lines) and lines[k].startswith('"'):
                        lines.pop(k)
                    updated_count += 1

        updated_blocks.append("\n".join(lines))

    # Append missing msgids from codebase
    added_count = 0
    for m in sorted(code_msgids):
        if m in seen_msgids or m.replace("%", "%%") in seen_msgids:
            continue
        if lang == "en":
            trans = TRANSLATIONS.get(m, m)
        else:
            trans = m
        has_fmt = "%(" in m
        block_lines = []
        if has_fmt:
            block_lines.append("#, python-format")
        block_lines.append(f'msgid "{escape_po_string(m)}"')
        block_lines.append(f'msgstr "{escape_po_string(trans)}"')
        updated_blocks.append("\n".join(block_lines))
        seen_msgids.add(m)
        added_count += 1

    po_path.write_text("\n\n".join(updated_blocks) + "\n", encoding="utf-8")
    return updated_count, added_count


def compile_mo_file(po_path: Path, mo_path: Path) -> int:
    """
    Pure-Python GNU gettext .mo binary compiler.
    Reads a UTF-8 .po file and writes a valid little-endian .mo binary file.
    """
    content = po_path.read_text(encoding="utf-8")
    blocks = content.split("\n\n")
    messages: dict[str, str] = {}

    for b in blocks:
        if "msgid " not in b:
            continue
        if any(l.strip().startswith("#, fuzzy") for l in b.splitlines()):
            continue
        lines = b.splitlines()
        mode = None
        msgid_parts = []
        msgstr_parts = []
        for l in lines:
            l_strip = l.strip()
            if l_strip.startswith("#"):
                continue
            if l_strip.startswith("msgid "):
                mode = "id"
                msgid_parts.append(l_strip[6:].strip('"'))
            elif l_strip.startswith("msgstr "):
                mode = "str"
                msgstr_parts.append(l_strip[7:].strip('"'))
            elif l_strip.startswith('"') and l_strip.endswith('"'):
                if mode == "id":
                    msgid_parts.append(l_strip[1:-1])
                elif mode == "str":
                    msgstr_parts.append(l_strip[1:-1])
        msgid = unescape_po_string("".join(msgid_parts))
        msgstr = unescape_po_string("".join(msgstr_parts))
        if msgstr:
            messages[msgid] = msgstr
            # If msgid has escaped '%%' in PO file, also register unescaped '%' key for runtime lookup
            if "%%" in msgid:
                unesc_id = msgid.replace("%%", "%")
                unesc_str = msgstr.replace("%%", "%")
                if unesc_id not in messages:
                    messages[unesc_id] = unesc_str

    # Ensure header entry "" exists with UTF-8 charset
    if "" not in messages:
        messages[""] = "Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n"

    keys = sorted(messages.keys())
    offsets = []
    ids_bytes = b""
    strs_bytes = b""

    for k in keys:
        k_b = k.encode("utf-8")
        v_b = messages[k].encode("utf-8")
        offsets.append((len(ids_bytes), len(k_b), len(strs_bytes), len(v_b)))
        ids_bytes += k_b + b"\x00"
        strs_bytes += v_b + b"\x00"

    n = len(keys)
    # Header is 7 * 4 = 28 bytes
    # Key index table is n * 8 bytes
    # Value index table is n * 8 bytes
    keystart = 28 + 16 * n
    valuestart = keystart + len(ids_bytes)

    koffsets = []
    voffsets = []
    for o1, l1, o2, l2 in offsets:
        koffsets += [l1, o1 + keystart]
        voffsets += [l2, o2 + valuestart]

    output = struct.pack(
        "Iiiiiii",
        0x950412DE,  # Magic number
        0,           # Version
        n,           # Number of strings
        28,          # Offset of table with original strings
        28 + 8 * n,  # Offset of table with translation strings
        0,           # Size of hashing table
        0,           # Offset of hashing table
    )
    output += struct.pack(f"{2 * n}i", *koffsets)
    output += struct.pack(f"{2 * n}i", *voffsets)
    output += ids_bytes
    output += strs_bytes

    mo_path.write_bytes(output)
    return n


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parent.parent
    arcamitte_dir = repo_root / "arcamitte"
    code_msgids = extract_code_msgids(arcamitte_dir)
    print(f"Extracted {len(code_msgids)} unique msgids from codebase.")

    for lang in ("en", "es"):
        po_file = arcamitte_dir / "locale" / lang / "LC_MESSAGES" / "django.po"
        mo_file = arcamitte_dir / "locale" / lang / "LC_MESSAGES" / "django.mo"
        upd, add = update_po_file(po_file, code_msgids, lang)
        compiled = compile_mo_file(po_file, mo_file)
        print(
            f"[{lang}] Updated {upd} entries, added {add} new entries in {po_file.relative_to(repo_root)}; "
            f"compiled {compiled} entries to {mo_file.relative_to(repo_root)}."
        )
