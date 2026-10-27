#!/usr/bin/env python3
"""
Generates idiomatic English translations for all strings in arcamitte/locale/en/LC_MESSAGES/django.po
"""

import os
import re
import sys

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
    "Superusers, Staff y Admins UO": "Superusers, Staff and UO Admins",
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
    "Estado Operativo": "Operational Status",
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
    "Trámites Recibidos por UO": "Procedures Received by UO",
    "Documentos dirigidos hacia esta dependencia organizativa": "Documents addressed to this organizational unit",
    "Asientos creados o consumidos en esta fecha": "Entries created or consumed on this date",
    "Asientos registrados bajo el perímetro y filtros seleccionados": "Entries recorded under the selected scope and filters",
    "Superusuario Global": "Global Superuser",
    "Personal Administrativo": "Administrative Staff",
    "Usuario Estándar": "Standard User",
}


def translate_po(po_file_path: str) -> int:
    with open(po_file_path, "r", encoding="utf-8") as f:
        content = f.read()

    blocks = content.split("\n\n")
    updated_blocks = []
    translated_count = 0

    for b in blocks:
        if not b.strip():
            continue
        lines = b.split("\n")
        msgid_parts = []
        msgstr_idx = -1

        for i, l in enumerate(lines):
            if l.startswith("msgid "):
                msgid_parts.append(l[6:].strip('"'))
            elif msgid_parts and l.startswith('"') and msgstr_idx == -1:
                msgid_parts.append(l.strip('"'))
            elif l.startswith("msgstr "):
                msgstr_idx = i

        full_msgid = "".join(msgid_parts)

        if msgstr_idx != -1 and full_msgid in TRANSLATIONS:
            curr_msgstr = lines[msgstr_idx][7:].strip('"')
            if not curr_msgstr or curr_msgstr == '""':
                trans = TRANSLATIONS[full_msgid].replace('"', '\\"')
                lines[msgstr_idx] = f'msgstr "{trans}"'
                k = msgstr_idx + 1
                while k < len(lines) and lines[k].startswith('"'):
                    lines.pop(k)
                translated_count += 1
                b = "\n".join(lines)

        updated_blocks.append(b)

    new_content = "\n\n".join(updated_blocks) + "\n"
    with open(po_file_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    return translated_count


if __name__ == "__main__":
    po_path = "arcamitte/locale/en/LC_MESSAGES/django.po"
    count = translate_po(po_path)
    print(f"Applied {count} translations to {po_path}")
