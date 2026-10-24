from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

from arcamitte.views import (
    APIDocumentStatusView,
    APIDocumentUploadView,
    PublicAccessRequestView,
    PublicConsumeView,
    RedeemOtpView,
    RequestAccessView,
    set_language_view,
)

urlpatterns = [
    # Redirección de raíz al formulario de solicitud pública
    path("", RedirectView.as_view(pattern_name="arcamitte:request-access", permanent=False), name="root-redirect"),
    # Vistas Web Públicas en la raíz del microservicio
    path("solicitar/", RequestAccessView.as_view(), name="web-request-access"),
    path("canjear/", RedeemOtpView.as_view(), name="web-redeem-otp"),
    path("set-language/", set_language_view, name="web-set-language"),
    # Endpoints directos de API REST v1 para microservicios y aplicaciones externas
    path("api/v1/documents/", APIDocumentUploadView.as_view(), name="api-v1-documents-upload"),
    path("api/v1/documents/<str:file_hash>/status/", APIDocumentStatusView.as_view(), name="api-v1-documents-status"),
    path("api/v1/request-access/", PublicAccessRequestView.as_view(), name="api-v1-request-access"),
    path("api/v1/consume/", PublicConsumeView.as_view(), name="api-v1-consume"),
    # Panel de administración tradicional de Django
    path("admin/", admin.site.urls),
    # Panel de administración Arcamitte (Vistas Django con Bootstrap 5 para la administración del microservicio)
    path("dashboard/", include("arcamitte.dashboard_urls", namespace="dashboard")),
    # Espacio de nombres arcamitte
    path("arcamitte/", include("arcamitte.urls", namespace="arcamitte")),
]

# Servir archivos cifrados en desarrollo / staging
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
