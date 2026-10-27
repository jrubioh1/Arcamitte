import configparser
import logging
import shutil
from pathlib import Path
from typing import Any

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.utils import timezone

logger = logging.getLogger(__name__)

from arcamitte.models import (
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
)
from arcamitte.services import (
    process_batch_import_json,
    shred_and_delete_file,
    upload_and_encrypt_document,
)

User = get_user_model()

MINIMAL_VALID_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R/Resources<<>>>>endobj\n"
    b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000053 00000 n \n0000000102 00000 n \n"
    b"trailer<</Size 4/Root 1 0 R>>\nstartxref\n178\n%%EOF\n"
)


class Command(BaseCommand):
    help = (
        "Inicializa y monta de forma 100% desatendida el entorno de Staging Sandbox de Arcamitte:\n"
        "- Genera arcamitte.ini desde la plantilla si no existe.\n"
        "- Aplica migraciones de base de datos.\n"
        "- Configura Administrador Maestro.\n"
        "- Crea la malla de Unidades Organizativas y usuarios con roles por departamento.\n"
        "- Genera y cifra documentos confidenciales de prueba (FIRST_ACCESS y ALL_RECIPIENTS).\n"
        "- Muestra un panel interactivo con credenciales, hashes y enlaces directos."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--clean",
            action="store_true",
            help="Restablece la base de datos y la carpeta media antes de montar el entorno.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        clean: bool = options.get("clean", False)
        base_dir = Path(settings.BASE_DIR)

        # ----------------------------------------------------------------------
        # 1. Configuración de arcamitte.ini para Staging
        # ----------------------------------------------------------------------
        self.stdout.write(self.style.MIGRATE_HEADING("=== 1. Comprobando fichero de configuración arcamitte.ini ==="))
        ini_file = base_dir / "arcamitte.ini"
        template_file = base_dir / "arcamitte.ini.template"

        if not ini_file.exists():
            if template_file.exists():
                shutil.copy(template_file, ini_file)
                self.stdout.write(self.style.SUCCESS(f"✓ Creado 'arcamitte.ini' a partir de '{template_file.name}'."))
            else:
                ini_file.touch()
                self.stdout.write(self.style.WARNING(f"✓ Creado 'arcamitte.ini' en {ini_file}."))
        else:
            self.stdout.write(self.style.NOTICE(f"✓ Fichero 'arcamitte.ini' detectado y activo en: {ini_file}."))

        # En Staging garantizamos que el backend de correo sea ConsoleBackend
        # para que los correos y códigos OTP se muestren de forma directa y desatendida en terminal
        cfg = configparser.ConfigParser()
        cfg.read(ini_file, encoding="utf-8")
        if not cfg.has_section("django"):
            cfg.add_section("django")
        if not cfg.has_option("django", "csrf_trusted_origins"):
            cfg.set("django", "csrf_trusted_origins", "http://localhost:8000,http://127.0.0.1:8000,http://0.0.0.0:8000")
        if not cfg.has_section("database"):
            cfg.add_section("database")
            cfg.set("database", "engine", "sqlite3")
            cfg.set("database", "name", "db.sqlite3")
        if not cfg.has_section("email"):
            cfg.add_section("email")
        cfg.set("email", "backend", "django.core.mail.backends.console.EmailBackend")

        # Si la clave Fernet contiene el valor provisional 'cambiame',
        # generamos una clave segura para este entorno de pruebas y la persistimos en arcamitte.ini
        current_fernet = cfg.get("security", "fernet_key", fallback="")
        if not current_fernet or "cambiame" in current_fernet.lower():
            from cryptography.fernet import Fernet
            new_key = Fernet.generate_key().decode()
            if not cfg.has_section("security"):
                cfg.add_section("security")
            cfg.set("security", "fernet_key", new_key)
            self.stdout.write(self.style.SUCCESS("✓ Generada clave 'fernet_key' para staging y guardada en arcamitte.ini."))

        with open(ini_file, "w", encoding="utf-8") as f:
            cfg.write(f)
        self.stdout.write(self.style.SUCCESS("✓ Configuración de staging guardada (correo en 'console', CSRF trusted origins y base de datos configurada)."))

        # ----------------------------------------------------------------------
        # 2. Limpieza opcional y migraciones
        # ----------------------------------------------------------------------
        if clean:
            self.stdout.write(self.style.WARNING("=== Modo --clean activado: limpiando entorno previo ==="))
            db_path = base_dir / "db.sqlite3"
            if db_path.exists():
                db_path.unlink()
                self.stdout.write("  • Base de datos db.sqlite3 eliminada.")
            media_path = Path(settings.MEDIA_ROOT)
            if media_path.exists():
                shutil.rmtree(media_path, ignore_errors=True)
                self.stdout.write("  • Directorio media/ limpiado.")

        self.stdout.write(self.style.MIGRATE_HEADING("=== 2. Ejecutando migraciones de base de datos ==="))
        call_command("migrate", interactive=False)
        self.stdout.write(self.style.SUCCESS("✓ Migraciones aplicadas correctamente."))

        # ----------------------------------------------------------------------
        # 3. Superusuario / Administrador Maestro
        # ----------------------------------------------------------------------
        # El Administrador Maestro se aprovisiona limpiamente dentro del lote JSON
        # mediante su rol institucional 'is_global_admin=True'.

        # ----------------------------------------------------------------------
        # 4. Carga Masiva de Malla de UOs y Usuarios Departamentales
        # ----------------------------------------------------------------------
        self.stdout.write(self.style.MIGRATE_HEADING("=== 4. Montando Malla de Unidades Organizativas y Roles ==="))
        data = {
            "organizational_units": [
                {
                    "numeric_code": 1001,
                    "alias": "DIRECCION",
                    "name": "Dirección General y Presidencia",
                    "email": "direccion@arcamitte.local",
                },
                {
                    "numeric_code": 1002,
                    "alias": "RRHH",
                    "name": "Recursos Humanos y Relaciones Laborales",
                    "email": "rrhh@arcamitte.local",
                },
                {
                    "numeric_code": 1003,
                    "alias": "LEGAL",
                    "name": "Asesoría Jurídica y Cumplimiento",
                    "email": "legal@arcamitte.local",
                },
                {
                    "numeric_code": 1004,
                    "alias": "AUDITORIA",
                    "name": "Auditoría Interna y Control de Gestión",
                    "email": "auditoria@arcamitte.local",
                },
            ],
            "users": [
                {
                    "username": "admin",
                    "email": "admin@arcamitte.local",
                    "first_name": "Administrador",
                    "last_name": "Maestro",
                    "password": "AdminMaster#2026",
                    "is_global_admin": True,
                    "must_change_password": False,
                },
                {
                    "username": "admin_dir",
                    "email": "admin_dir@arcamitte.local",
                    "password": "PasswordDir#2026",
                    "uo_alias": "DIRECCION",
                    "role": "ADMIN",
                },
                {
                    "username": "gestor_rrhh",
                    "email": "gestor_rrhh@arcamitte.local",
                    "password": "PasswordRRHH#2026",
                    "uo_alias": "RRHH",
                    "role": "OPERATOR",
                },
                {
                    "username": "auditor_rrhh",
                    "email": "auditor_rrhh@arcamitte.local",
                    "password": "PasswordAuditor#2026",
                    "uo_alias": "RRHH",
                    "role": "AUDITOR",
                },
                {
                    "username": "gestor_legal",
                    "email": "gestor_legal@arcamitte.local",
                    "password": "PasswordLegal#2026",
                    "uo_alias": "LEGAL",
                    "role": "OPERATOR",
                },
                {
                    "username": "auditor_general",
                    "email": "auditor_gral@arcamitte.local",
                    "password": "PasswordAudGral#2026",
                    "uo_alias": "AUDITORIA",
                    "role": "AUDITOR",
                },
            ],
        }

        uos_count, users_count, _ = process_batch_import_json(data)
        self.stdout.write(self.style.SUCCESS(f"✓ Creadas/Actualizadas {uos_count} UOs y {users_count} usuarios con roles y permisos sincronizados."))

        # ----------------------------------------------------------------------
        # 5. Generación y Cifrado Desatendido de Documentos de Demostración
        # ----------------------------------------------------------------------
        self.stdout.write(self.style.MIGRATE_HEADING("=== 5. Generando Documentos Cifrados en la Malla ==="))
        uo_rrhh = OrganizationalUnit.objects.filter(alias="RRHH").first()
        uo_legal = OrganizationalUnit.objects.filter(alias="LEGAL").first()
        uo_dir = OrganizationalUnit.objects.filter(alias="DIRECCION").first()
        user_rrhh = User.objects.filter(username="gestor_rrhh").first()
        user_legal = User.objects.filter(username="gestor_legal").first()

        # Documento 1: RRHH -> LEGAL (FIRST_ACCESS)
        pdf_bytes_1 = MINIMAL_VALID_PDF + b"% Expediente RRHH confidencial de prueba 2026\n"
        upload_1 = SimpleUploadedFile("expediente_laboral_confidencial.pdf", pdf_bytes_1, content_type="application/pdf")
        doc_1 = upload_and_encrypt_document(
            original_file=upload_1,
            allowed_emails=["gestor_legal@arcamitte.local", "auditor_rrhh@arcamitte.local"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            description="Expediente disciplinario y pericial de prueba para cotejo legal confidencial.",
            origin_uo=uo_rrhh,
            target_uo=uo_legal,
            uploaded_by=user_rrhh,
            reopen_existing=True,
        )

        # Documento 2: LEGAL -> DIRECCION (ALL_RECIPIENTS - multi-destinatario)
        pdf_bytes_2 = MINIMAL_VALID_PDF + b"% Acta confidencial junta general 2026\n"
        upload_2 = SimpleUploadedFile("acuerdo_confidencial_junta.pdf", pdf_bytes_2, content_type="application/pdf")
        doc_2 = upload_and_encrypt_document(
            original_file=upload_2,
            allowed_emails=["admin_dir@arcamitte.local", "auditor_gral@arcamitte.local", "socio@externo.es"],
            burn_policy=EncryptedDocument.BurnPolicy.ALL_RECIPIENTS,
            description="Acta de la sesión extraordinaria del consejo con cláusulas de confidencialidad estricta.",
            origin_uo=uo_legal,
            target_uo=uo_dir,
            uploaded_by=user_legal,
            reopen_existing=True,
        )

        # Documento 3: Muestra de documento consumido (cumpliendo Burn-After-Read)
        pdf_bytes_3 = MINIMAL_VALID_PDF + b"% Informe archivado\n"
        upload_3 = SimpleUploadedFile("informe_auditoria_consumido.pdf", pdf_bytes_3, content_type="application/pdf")
        doc_3 = upload_and_encrypt_document(
            original_file=upload_3,
            allowed_emails=["auditor_rrhh@arcamitte.local"],
            burn_policy=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
            description="Auditoría previa ya consumida para pruebas de respuesta informativa post-consumo.",
            origin_uo=uo_rrhh,
            uploaded_by=user_rrhh,
            reopen_existing=True,
        )
        # Triturar físicamente el archivo del documento consumido (cumplimiento estricto Burn-After-Read NIST SP 800-88)
        if doc_3.encrypted_file:
            shred_and_delete_file(doc_3.encrypted_file)

        doc_3.is_consumed = True
        doc_3.consumed_by = "auditor_rrhh@arcamitte.local"
        doc_3.consumed_at = timezone.now()
        doc_3.consumed_recipients = ["auditor_rrhh@arcamitte.local"]
        doc_3.save(update_fields=["is_consumed", "consumed_by", "consumed_at", "consumed_recipients", "updated_at"])

        DocumentAccessLog.objects.create(
            document=doc_3,
            email="auditor_rrhh@arcamitte.local",
            action=DocumentAccessLog.Action.DESCIFRADO_EXITOSO_BURN,
            origin_uo=uo_rrhh,
            target_uo=None,
            ip_address="127.0.0.1",
            user_agent="Mozilla/5.0 (Staging Sandbox)",
            details="Entrega completada y archivo triturado físicamente (Burn-After-Read).",
        )

        # ----------------------------------------------------------------------
        # 6. Panel y Reporte Resumen
        # ----------------------------------------------------------------------
        base_url = "http://127.0.0.1:8000"
        self.stdout.write(self.style.SUCCESS("\n" + "=" * 95))
        self.stdout.write(self.style.SUCCESS("✅ ENTORNO DE STAGING SANDBOX MONTADO EXITOSAMENTE"))
        self.stdout.write(self.style.SUCCESS("=" * 95))

        self.stdout.write(self.style.NOTICE("\n🌐 ACCESOS WEB DISPONIBLES:"))
        self.stdout.write(f"   • Panel de Administración Arcamitte: {base_url}/dashboard/")
        self.stdout.write(f"   • Pasarela Pública (Pedir):          {base_url}/solicitar/")
        self.stdout.write(f"   • Pasarela Pública (Canjear):        {base_url}/canjear/")

        self.stdout.write(self.style.NOTICE("\n👥 CUENTAS DE USUARIO Y ROLES DISPONIBLES:"))
        self.stdout.write(f"   {'USUARIO':<18} {'CONTRASEÑA':<22} {'ROL / UO':<30} {'CORREO'}")
        self.stdout.write("   " + "-" * 90)
        self.stdout.write(f"   {'admin':<18} {'AdminMaster#2026':<22} {'Master Admin (Administrador Global)':<30} {'admin@arcamitte.local'}")
        self.stdout.write(f"   {'admin_dir':<18} {'PasswordDir#2026':<22} {'ADMIN en DIRECCION (1001)':<30} {'admin_dir@arcamitte.local'}")
        self.stdout.write(f"   {'gestor_rrhh':<18} {'PasswordRRHH#2026':<22} {'OPERATOR en RRHH (1002)':<30} {'gestor_rrhh@arcamitte.local'}")
        self.stdout.write(f"   {'auditor_rrhh':<18} {'PasswordAuditor#2026':<22} {'AUDITOR en RRHH (1002)':<30} {'auditor_rrhh@arcamitte.local'}")
        self.stdout.write(f"   {'gestor_legal':<18} {'PasswordLegal#2026':<22} {'OPERATOR en LEGAL (1003)':<30} {'gestor_legal@arcamitte.local'}")
        self.stdout.write(f"   {'auditor_general':<18} {'PasswordAudGral#2026':<22} {'AUDITOR en AUDITORIA (1004)':<30} {'auditor_gral@arcamitte.local'}")

        self.stdout.write(self.style.NOTICE("\n📄 DOCUMENTOS CIFRADOS DISPONIBLES PARA PRUEBA INMEDIATA:"))
        self.stdout.write("   1. [ACTIVO - FIRST_ACCESS] expediente_laboral_confidencial.pdf (RRHH -> LEGAL)")
        self.stdout.write(f"      • HASH (SHA-256): {doc_1.file_hash}")
        self.stdout.write("      • Correos autorizados: gestor_legal@arcamitte.local, auditor_rrhh@arcamitte.local")
        self.stdout.write(self.style.WARNING(f"      • Enlace 1-Clic: {base_url}/solicitar/?hash={doc_1.file_hash}"))

        self.stdout.write("\n   2. [ACTIVO - ALL_RECIPIENTS] acuerdo_confidencial_junta.pdf (LEGAL -> DIRECCION)")
        self.stdout.write(f"      • HASH (SHA-256): {doc_2.file_hash}")
        self.stdout.write("      • Correos autorizados: admin_dir@arcamitte.local, auditor_gral@arcamitte.local, socio@externo.es")
        self.stdout.write(self.style.WARNING(f"      • Enlace 1-Clic: {base_url}/solicitar/?hash={doc_2.file_hash}"))

        self.stdout.write("\n   3. [CONSUMIDO] informe_auditoria_consumido.pdf")
        self.stdout.write(f"      • HASH (SHA-256): {doc_3.file_hash}")
        self.stdout.write("      • Consumido por: auditor_rrhh@arcamitte.local (muestra respuesta post-consumo)")
        self.stdout.write(self.style.WARNING(f"      • Enlace 1-Clic: {base_url}/solicitar/?hash={doc_3.file_hash}"))

        self.stdout.write(self.style.NOTICE("\n💡 GUÍA DE PRUEBAS DE AISLAMIENTO MULTI-TENANT (ROLES Y UO):"))
        self.stdout.write("   • Usuario 'admin' (Administrador Global / CISO): Dispone de visibilidad global y puede seleccionar cualquier UO Emisora.")
        self.stdout.write("   • Usuarios departamentales (ej. 'gestor_rrhh' o 'gestor_legal'):")
        self.stdout.write("     - Al acceder a /dashboard/, el campo 'UO Emisora' se restringe automáticamente a las UOs en las que son miembros activos.")
        self.stdout.write("     - Solo visualizan documentos donde su UO figura como Emisora o Receptora en la Malla.")

        self.stdout.write(self.style.NOTICE("\n📧 CORREO ELECTRÓNICO EN STAGING (SALIDA DIRECTA EN CONSOLA):"))
        self.stdout.write("   • Configurado automáticamente en 'django.core.mail.backends.console.EmailBackend' para máxima simplicidad.")
        self.stdout.write("   • Al solicitar un documento en la pasarela (/solicitar/), el correo con el código OTP de 6 dígitos")
        self.stdout.write("     se imprimirá de forma inmediata en la terminal donde ejecutes 'manage.py runserver'.")
        self.stdout.write("   • Para despliegues de producción real, ajusta en 'arcamitte.ini' -> 'backend = django.core.mail.backends.smtp.EmailBackend'.")
        self.stdout.write("   • Además, siempre puedes auditar los tokens en tiempo real en:")

        self.stdout.write(self.style.SUCCESS("\n" + "=" * 95))
        self.stdout.write("Para arrancar el servidor web de desarrollo:")
        self.stdout.write(self.style.WARNING("  poetry run python manage.py runserver 8000"))
        self.stdout.write("Para ejecutar el script de flujo automatizado:")
        self.stdout.write(self.style.WARNING("  poetry run python scripts/demo_flow.py"))
        self.stdout.write(self.style.SUCCESS("=" * 95 + "\n"))
