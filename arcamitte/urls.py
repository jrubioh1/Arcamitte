from django.urls import path
from arcamitte.views import (
    APIDocumentStatusView,
    APIDocumentUploadView,
    PublicAccessRequestView,
    PublicConsumeView,
    RedeemOtpView,
    RequestAccessView,
    set_language_view,
)

app_name = "arcamitte"

urlpatterns = [
    # ==========================================================================
    # INTERFAZ GRÁFICA DE USUARIO (WEB GUI)
    # ==========================================================================
    path(
        "solicitar/",
        RequestAccessView.as_view(),
        name="request-access",
    ),
    path(
        "canjear/",
        RedeemOtpView.as_view(),
        name="redeem-otp",
    ),
    path(
        "set-language/",
        set_language_view,
        name="set-language",
    ),
    path(
        "",
        RequestAccessView.as_view(),
        name="index",
    ),
    # ==========================================================================
    # ENDPOINTS DE LA API REST v1 (MICROSERVICIO M2M Y PÚBLICO)
    # ==========================================================================
    path(
        "api/v1/documents/",
        APIDocumentUploadView.as_view(),
        name="api-v1-document-upload",
    ),
    path(
        "api/v1/documents/<str:file_hash>/status/",
        APIDocumentStatusView.as_view(),
        name="api-v1-document-status",
    ),
    path(
        "api/v1/request-access/",
        PublicAccessRequestView.as_view(),
        name="api-v1-request-access",
    ),
    path(
        "api/v1/consume/",
        PublicConsumeView.as_view(),
        name="api-v1-consume",
    ),
    # Retrocompatibilidad para integraciones previas
    path(
        "api/public/request-access/",
        PublicAccessRequestView.as_view(),
        name="api-public-request-access",
    ),
    path(
        "api/public/consume/",
        PublicConsumeView.as_view(),
        name="api-public-consume",
    ),
]
