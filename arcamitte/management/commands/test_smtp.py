import sys
from datetime import datetime
from django.conf import settings
from django.core.mail import get_connection, send_mail
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Prueba el envío de un correo electrónico real usando la configuración SMTP actual de Django."

    def add_arguments(self, parser):
        parser.add_argument("recipient", type=str, help="Dirección de correo electrónico donde enviar el mensaje de prueba.")

    def handle(self, *args, **options):
        recipient = options["recipient"]
        self.stdout.write(self.style.NOTICE("\n========================================================"))
        self.stdout.write(self.style.NOTICE("🔍 ARCAMITTE - DIAGNÓSTICO DE CONFIGURACIÓN SMTP / CORREO"))
        self.stdout.write(self.style.NOTICE("========================================================"))
        self.stdout.write(f"  EMAIL_BACKEND:       {settings.EMAIL_BACKEND}")
        self.stdout.write(f"  EMAIL_HOST:          {settings.EMAIL_HOST}")
        self.stdout.write(f"  EMAIL_PORT:          {settings.EMAIL_PORT}")
        self.stdout.write(f"  EMAIL_USE_TLS:       {settings.EMAIL_USE_TLS}")
        self.stdout.write(f"  EMAIL_USE_SSL:       {settings.EMAIL_USE_SSL}")
        self.stdout.write(f"  EMAIL_HOST_USER:     {settings.EMAIL_HOST_USER or '(no configurado)'}")
        self.stdout.write(f"  DEFAULT_FROM_EMAIL:  {settings.DEFAULT_FROM_EMAIL}")
        self.stdout.write(f"  Destinatario prueba: {recipient}")
        self.stdout.write("--------------------------------------------------------")

        if settings.EMAIL_BACKEND == "django.core.mail.backends.console.EmailBackend":
            self.stdout.write(
                self.style.WARNING(
                    "⚠️  Atención: EMAIL_BACKEND está configurado en modo CONSOLA.\n"
                    "   El mensaje se imprimirá en tu terminal y no viajará por internet.\n"
                    "   Para enviar correos reales, define host en arcamitte.ini.\n"
                )
            )

        self.stdout.write("Conectando con el servidor de correo y despachando mensaje...")

        subject = "[Arcamitte] Correo de prueba de configuración SMTP"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = (
            f"¡Hola!\n\n"
            f"Este es un correo de prueba enviado desde Arcamitte Staging el {now_str}.\n\n"
            f"Si estás leyendo este mensaje en tu bandeja de entrada, tu configuración SMTP\n"
            f"y tu archivo arcamitte.ini están correctamente configurados y operativos.\n\n"
            f"Atentamente,\n"
            f"Sistema de Seguridad Arcamitte"
        )

        try:
            connection = get_connection(fail_silently=False)
            connection.open()
            self.stdout.write(self.style.SUCCESS("  ✓ Handshake y conexión establecida con el servidor de correo."))

            send_mail(
                subject=subject,
                message=body,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[recipient],
                connection=connection,
                fail_silently=False,
            )
            connection.close()
            self.stdout.write(self.style.SUCCESS(f"\n✅ ¡ÉXITO TOTAL! Correo despachado correctamente a '{recipient}'."))
            self.stdout.write(self.style.SUCCESS("Revisa tu bandeja de entrada (y la carpeta de SPAM por si acaso).\n"))
        except Exception as exc:
            self.stdout.write(self.style.ERROR(f"\n❌ ERROR DE CONEXIÓN O ENVÍO: {exc}\n"))
            self.stdout.write(self.style.WARNING("Guía de solución:"))
            self.stdout.write("  1. Verifica que EMAIL_HOST_USER y EMAIL_HOST_PASSWORD en .env sean correctos.")
            self.stdout.write("  2. Si usas Gmail, asegúrate de crear una 'Contraseña de aplicación' de 16 caracteres")
            self.stdout.write("     en https://myaccount.google.com/apppasswords (no uses tu clave de Google normal).")
            self.stdout.write("  3. Si usas puerto 587, comprueba EMAIL_USE_TLS=True y EMAIL_USE_SSL=False.")
            self.stdout.write("  4. Si usas puerto 465, comprueba EMAIL_USE_TLS=False y EMAIL_USE_SSL=True.")
            self.stdout.write("  5. Comprueba si tu proveedor o cortafuegos bloquea puertos salientes 587/465.\n")
            sys.exit(1)
