from __future__ import annotations

from django.urls import path

from arcamitte import dashboard_views

app_name = "dashboard"

urlpatterns = [
    path("", dashboard_views.DashboardHomeView.as_view(), name="home"),
    path("modo/", dashboard_views.DashboardModeSelectionView.as_view(), name="mode_selection"),
    path("login/", dashboard_views.DashboardLoginView.as_view(), name="login"),
    path("logout/", dashboard_views.DashboardLogoutView.as_view(), name="logout"),
    path("olvide-password/", dashboard_views.DashboardPasswordResetRequestView.as_view(), name="password_reset_request"),
    path("cambiar-password/", dashboard_views.DashboardPasswordChangeView.as_view(), name="password_change"),
    path("documentos/", dashboard_views.DashboardDocumentListView.as_view(), name="document_list"),
    path("documentos/nuevo/", dashboard_views.DashboardDocumentUploadView.as_view(), name="document_upload"),
    path("documentos/<str:file_hash>/", dashboard_views.DashboardDocumentDetailView.as_view(), name="document_detail"),
    path("documentos/<str:file_hash>/auditar/", dashboard_views.DashboardDocumentAuditDownloadView.as_view(), name="document_audit_download"),
    path("documentos/<str:file_hash>/terminar/", dashboard_views.DashboardDocumentTerminateView.as_view(), name="document_terminate"),
    path("auditoria/", dashboard_views.DashboardAuditLogView.as_view(), name="audit_logs"),
    path("unidades-organizativas/", dashboard_views.DashboardUOListView.as_view(), name="uo_list"),
    path("unidades-organizativas/nueva/", dashboard_views.DashboardUOCreateView.as_view(), name="uo_create"),
    path("unidades-organizativas/<int:uo_id>/editar/", dashboard_views.DashboardUOEditView.as_view(), name="uo_edit"),
    path("unidades-organizativas/<int:uo_id>/miembros/", dashboard_views.DashboardUOMembersView.as_view(), name="uo_members"),
    path("api/uo/<int:uo_id>/members/", dashboard_views.DashboardUOMembersAjaxView.as_view(), name="uo_members_ajax"),
    path("usuarios/", dashboard_views.DashboardUserListView.as_view(), name="user_list"),
    path("usuarios/nuevo/", dashboard_views.DashboardUserCreateView.as_view(), name="user_create"),
    path("usuarios/<int:user_id>/editar/", dashboard_views.DashboardUserEditView.as_view(), name="user_edit"),
    path("usuarios/<int:user_id>/reset-password/", dashboard_views.DashboardUserResetPasswordView.as_view(), name="user_reset_password"),
    path("tokens/", dashboard_views.DashboardApiTokenView.as_view(), name="api_tokens"),
    path("tokens/<int:token_id>/revocar/", dashboard_views.DashboardApiTokenRevokeView.as_view(), name="api_token_revoke"),
]
