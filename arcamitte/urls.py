from django.urls import path
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
    # SUITE SEGURA DE LA API REST v1 (INGESTA Y CONSULTA DE ESTADO)
    # ==========================================================================
    path(
        "api/v1/health/",
        APIHealthCheckView.as_view(),
        name="api-v1-health",
    ),
    path(
        "api/v1/documents/check-hash/",
        APIDocumentCheckHashView.as_view(),
        name="api-v1-document-check-hash",
    ),
    path(
        "api/v1/documents/",
        APIDocumentRootView.as_view(),
        name="api-v1-document-upload",
    ),
    path(
        "api/v1/documents/<str:file_hash>/",
        APIDocumentDetailView.as_view(),
        name="api-v1-document-detail",
    ),
    path(
        "api/v1/documents/<str:file_hash>/status/",
        APIDocumentStatusView.as_view(),
        name="api-v1-document-status",
    ),
    path(
        "api/v1/documents/<str:file_hash>/email-template/",
        APIDocumentEmailTemplateView.as_view(),
        name="api-v1-document-email-template",
    ),
    path(
        "api/v1/uos/",
        APIOUListView.as_view(),
        name="api-v1-uo-list",
    ),
    path(
        "api/v1/uos/<str:identifier>/recipients/",
        APIOURecipientsView.as_view(),
        name="api-v1-uo-recipients",
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
]
