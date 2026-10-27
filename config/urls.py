from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

from arcamitte.views import (
    APIDocumentCheckHashView,
    APIDocumentDetailView,
    APIDocumentEmailTemplateView,
    APIDocumentRootView,
    APIDocumentStatusView,
    APIHealthCheckView,
    APIOUListView,
    APIOURecipientsView,
    PublicAccessRequestView,
    PublicConsumeView,
    RedeemOtpView,
    RequestAccessView,
    set_language_view,
)

urlpatterns = [
    # Redirección de raíz al formulario de solicitud pública
    path(
        "",
        RedirectView.as_view(pattern_name="arcamitte:request-access", permanent=False),
        name="root-redirect",
    ),
    # Vistas Web Públicas en la raíz del microservicio
    path("solicitar/", RequestAccessView.as_view(), name="web-request-access"),
    path("canjear/", RedeemOtpView.as_view(), name="web-redeem-otp"),
    path("set-language/", set_language_view, name="web-set-language"),
    # ==========================================================================
    # ESQUEMA Y DOCUMENTACIÓN INTERACTIVA OPENAPI 3.0 (SWAGGER / REDOC)
    # ==========================================================================
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    # ==========================================================================
    # SUITE SEGURA DIRECTA DE LA API REST v1 (INGESTA Y CONSULTA DE ESTADO)
    # ==========================================================================
    path("api/v1/health/", APIHealthCheckView.as_view(), name="api-v1-health"),
    path(
        "api/v1/documents/check-hash/",
        APIDocumentCheckHashView.as_view(),
        name="api-v1-documents-check-hash",
    ),
    path(
        "api/v1/documents/",
        APIDocumentRootView.as_view(),
        name="api-v1-documents-upload",
    ),
    path(
        "api/v1/documents/<str:file_hash>/",
        APIDocumentDetailView.as_view(),
        name="api-v1-documents-detail",
    ),
    path(
        "api/v1/documents/<str:file_hash>/status/",
        APIDocumentStatusView.as_view(),
        name="api-v1-documents-status",
    ),
    path(
        "api/v1/documents/<str:file_hash>/email-template/",
        APIDocumentEmailTemplateView.as_view(),
        name="api-v1-documents-email-template",
    ),
    path("api/v1/uos/", APIOUListView.as_view(), name="api-v1-uos-list"),
    path(
        "api/v1/uos/<str:identifier>/recipients/",
        APIOURecipientsView.as_view(),
        name="api-v1-uos-recipients",
    ),
    path(
        "api/v1/request-access/",
        PublicAccessRequestView.as_view(),
        name="api-v1-request-access",
    ),
    path("api/v1/consume/", PublicConsumeView.as_view(), name="api-v1-consume"),
    # Panel de administración tradicional de Django (con salvaguardas e inmutabilidad de ModelAdmin)
    path("admin/", admin.site.urls),
    # Panel de administración Arcamitte (Vistas Django con Bootstrap 5 para la administración del microservicio)
    path("dashboard/", include("arcamitte.dashboard_urls", namespace="dashboard")),
    # Espacio de nombres arcamitte
    path("arcamitte/", include("arcamitte.urls", namespace="arcamitte")),
]

# Servir archivos cifrados en desarrollo / staging
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
