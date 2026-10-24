from __future__ import annotations

from django.urls import path

from arcamitte import dashboard_views

app_name = "dashboard"

urlpatterns = [
    path("", dashboard_views.DashboardHomeView.as_view(), name="home"),
    path("login/", dashboard_views.DashboardLoginView.as_view(), name="login"),
    path("logout/", dashboard_views.DashboardLogoutView.as_view(), name="logout"),
    path("documentos/", dashboard_views.DashboardDocumentListView.as_view(), name="document_list"),
    path("documentos/nuevo/", dashboard_views.DashboardDocumentUploadView.as_view(), name="document_upload"),
    path("documentos/<str:file_hash>/", dashboard_views.DashboardDocumentDetailView.as_view(), name="document_detail"),
    path("documentos/<str:file_hash>/terminar/", dashboard_views.DashboardDocumentTerminateView.as_view(), name="document_terminate"),
    path("auditoria/", dashboard_views.DashboardAuditLogView.as_view(), name="audit_logs"),
    path("unidades-organizativas/", dashboard_views.DashboardUOListView.as_view(), name="uo_list"),
    path("api/uo/<int:uo_id>/members/", dashboard_views.DashboardUOMembersAjaxView.as_view(), name="uo_members_ajax"),
    path("tokens/", dashboard_views.DashboardApiTokenView.as_view(), name="api_tokens"),
    path("tokens/<int:token_id>/revocar/", dashboard_views.DashboardApiTokenRevokeView.as_view(), name="api_token_revoke"),
]
