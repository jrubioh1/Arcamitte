from __future__ import annotations

import configparser
import os
from pathlib import Path
from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent.parent

# ==============================================================================
# CARGA DE CONFIGURACIÓN DIRECTA (arcamitte.ini / arcamitte.ini.template)
# ==============================================================================
ini_env = os.environ.get("ARCAMITTE_INI_PATH")
if ini_env and Path(ini_env).is_file():
    config_file = Path(ini_env)
elif (BASE_DIR / "arcamitte.ini").is_file():
    config_file = BASE_DIR / "arcamitte.ini"
elif (BASE_DIR / "arcamitte.ini.template").is_file():
    config_file = BASE_DIR / "arcamitte.ini.template"
else:
    config_file = None

config = configparser.ConfigParser()
if config_file and config_file.exists():
    config.read(config_file, encoding="utf-8")

# Clave secreta estándar para Django
SECRET_KEY = config.get(
    "django",
    "secret_key",
    fallback="django-insecure-staging-key-arcamitte-cybersec-demo-2026!#@$",
)

DEBUG = config.getboolean("django", "debug", fallback=True)

allowed_hosts_str = config.get("django", "allowed_hosts", fallback="*")
ALLOWED_HOSTS = [h.strip() for h in allowed_hosts_str.split(",") if h.strip()]

# Orígenes confiables para protección CSRF (OWASP A05 & Django 4+)
csrf_trusted_origins_str = config.get("django", "csrf_trusted_origins", fallback="")
if csrf_trusted_origins_str:
    CSRF_TRUSTED_ORIGINS = [o.strip() for o in csrf_trusted_origins_str.split(",") if o.strip()]
else:
    CSRF_TRUSTED_ORIGINS = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://0.0.0.0:8000",
    ]

# Soporte para túneles y balanceadores / proxies inversos (Nginx, Traefik, Docker)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Hardening de cookies de sesión, CSRF e idioma (NIST SP 800-63B / OWASP A05)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = not DEBUG

CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = not DEBUG

LANGUAGE_COOKIE_HTTPONLY = True
LANGUAGE_COOKIE_SAMESITE = "Lax"
LANGUAGE_COOKIE_SECURE = not DEBUG

# Endurecimiento de cabeceras HTTP de seguridad (OWASP A05 / Django Deployment Checklist)
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

if not DEBUG:
    SECURE_SSL_REDIRECT = config.getboolean("django", "secure_ssl_redirect", fallback=True)
    SECURE_HSTS_SECONDS = config.getint("django", "secure_hsts_seconds", fallback=31536000)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Django REST Framework
    "rest_framework",
    # Arcamitte Application
    "arcamitte.apps.ArcamitteConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "arcamitte.middleware.RequirePasswordChangeMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.template.context_processors.i18n",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "arcamitte.context_processors.arcamitte_dashboard_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# ==============================================================================
# CONFIGURACIÓN MULTIBASE DE DATOS (SQLite / PostgreSQL)
# ==============================================================================
db_engine = config.get("database", "engine", fallback="sqlite3").strip().lower()
db_name = config.get("database", "name", fallback="db.sqlite3").strip()

if db_engine in ("postgresql", "postgres"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": db_name,
            "USER": config.get("database", "user", fallback=""),
            "PASSWORD": config.get("database", "password", fallback=""),
            "HOST": config.get("database", "host", fallback="localhost"),
            "PORT": config.get("database", "port", fallback="5432"),
        }
    }
else:
    db_path = BASE_DIR / db_name if not Path(db_name).is_absolute() else Path(db_name)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": db_path,
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 6}},
]

LANGUAGE_CODE = "es"
LANGUAGES = [
    ("es", "Español"),
    ("en", "English"),
]
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
LOCALE_PATHS = [
    BASE_DIR / "arcamitte" / "locale",
]

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = []
if (BASE_DIR / "arcamitte" / "static").exists():
    STATICFILES_DIRS.append(BASE_DIR / "arcamitte" / "static")

# Almacenamiento multimedia para documentos cifrados
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ==============================================================================
# CONFIGURACIÓN DE ARCAMITTE Y CRIPTOGRAFÍA
# ==============================================================================

# Clave maestra Fernet (32 bytes url-safe base64) para cifrar las claves de datos (DEK).
raw_fernet = config.get(
    "security",
    "fernet_key",
    fallback="cambiame-cambiame-cambiame-cambiame-cambiame=",
)

try:
    Fernet(raw_fernet.encode("utf-8"))
    ARCAMITTE_FERNET_KEY = raw_fernet
except Exception as exc:
    if DEBUG:
        ARCAMITTE_FERNET_KEY = Fernet.generate_key().decode()
    else:
        from django.core.exceptions import ImproperlyConfigured

        raise ImproperlyConfigured(
            f"[ARCAMITTE SECURITY CRITICAL] 'ARCAMITTE_FERNET_KEY' no es válida o mantiene el valor de plantilla ('cambiame...'): {exc}. "
            "En entornos de producción (DEBUG=False) es obligatorio configurar una clave simétrica real de 32 bytes base64 url-safe."
        ) from exc

# Tamaño máximo de archivo permitido (50 MB)
ARCAMITTE_MAX_FILE_SIZE = config.getint("security", "max_file_size", fallback=50 * 1024 * 1024)
ARCAMITTE_TIMING_PBKDF2_ITERATIONS = config.getint("security", "timing_pbkdf2_iterations", fallback=20000)

# ==============================================================================
# CONFIGURACIÓN DE CORREO ELECTRÓNICO (SMTP CORPORATIVO POR DEFECTO)
# ==============================================================================
EMAIL_BACKEND = config.get(
    "email",
    "backend",
    fallback="django.core.mail.backends.smtp.EmailBackend",
)
EMAIL_HOST = config.get("email", "host", fallback="localhost")
EMAIL_PORT = config.getint("email", "port", fallback=25)
EMAIL_USE_TLS = config.getboolean("email", "use_tls", fallback=False)
EMAIL_USE_SSL = config.getboolean("email", "use_ssl", fallback=False)
EMAIL_HOST_USER = config.get("email", "host_user", fallback="")
EMAIL_HOST_PASSWORD = config.get("email", "host_password", fallback="")
DEFAULT_FROM_EMAIL = config.get("email", "default_from_email", fallback="no-reply@arcamitte.local")
EMAIL_TIMEOUT = config.getint("email", "timeout", fallback=5)
ARCAMITTE_ASYNC_EMAIL = config.getboolean("email", "async_email", fallback=True)
ARCAMITTE_EMAIL_MAX_WORKERS = config.getint("email", "email_max_workers", fallback=8)
ARCAMITTE_WEB_REQUEST_LIMIT_PER_MINUTE = config.getint("throttling", "web_request_limit_per_minute", fallback=15)

# Caché en memoria para limitación de peticiones y control anti-flood
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "arcamitte-cache",
    }
}

# Configuración DRF genérica con soporte para tokens de alta seguridad
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "arcamitte.authentication.APITokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.BasicAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/minute",
        "access_request": config.get("throttling", "api_access_request_rate", fallback="15/minute"),
        "access_consume": config.get("throttling", "api_access_consume_rate", fallback="30/minute"),
    },
}

# Redirecciones de Autenticación para el Dashboard
LOGIN_URL = "dashboard:login"
LOGIN_REDIRECT_URL = "dashboard:home"
LOGOUT_REDIRECT_URL = "dashboard:login"
