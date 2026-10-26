from __future__ import annotations

import io
import json
from typing import Any, List, Optional
from urllib.parse import quote

from django import forms
from django.contrib import admin, messages
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.core.exceptions import PermissionDenied
from django.db import models
from django.http import FileResponse, Http404, HttpRequest, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import path, reverse
from django.utils import timezone
from django.utils.html import format_html, format_html_join
from django.utils.translation import gettext_lazy as _

from arcamitte.models import (
    AccessVerificationToken,
    DocumentAccessLog,
    EncryptedDocument,
    OrganizationalUnit,
    UserUOMembership,
    default_document_expiry,
)
from arcamitte.services import (
    admin_decrypt_document,
    calculate_file_sha256,
    generate_corporate_email_text,
    process_batch_import_json,
    reactivate_document,
    terminate_document_manually,
    upload_and_encrypt_document,
)
from arcamitte.validators import normalize_and_validate_email_list, validate_document_file
from arcamitte.utils import (
    apply_no_store_headers,
    get_client_ip,
    sanitize_content_disposition_filename,
)


class EmailListAdminWidget(forms.Widget):
    """
    Widget interactivo para Django Admin que permite gestionar correos autorizados
    mediante campos dinámicos individuales con botones '➕' y '✕'.
    Diseño 100% responsive con contador dinámico y ajuste automático a cualquier ancho de pantalla.
    """

    def render(self, name: str, value: Any, attrs: Optional[dict] = None, renderer: Any = None) -> Any:
        if value is None:
            email_list = []
        elif isinstance(value, list):
            email_list = value
        elif isinstance(value, str):
            try:
                parsed = json.loads(value)
                email_list = parsed if isinstance(parsed, list) else [value]
            except Exception:
                email_list = [e.strip() for e in value.split(",") if e.strip()]
        else:
            email_list = []

        if not email_list:
            email_list = [""]

        rows_rendered = format_html_join(
            "\n",
            '<div class="admin-email-row" style="display:flex; gap:8px; margin-bottom:8px; align-items:center; width:100%; max-width:520px; box-sizing:border-box;">'
            '<input type="email" name="{}" value="{}" class="vTextField" style="flex:1 1 auto; min-width:0; width:100%; height:34px; padding:6px 10px; border-radius:4px; box-sizing:border-box;" placeholder="destinatario@empresa.com" required>'
            '<button type="button" class="button btn-remove-row" onclick="removeAdminRow(this)" style="flex:0 0 34px; width:34px; height:34px; background:#ba2121; color:#fff; border:none; border-radius:4px; padding:0; display:inline-flex; align-items:center; justify-content:center; cursor:pointer; font-size:1rem; font-weight:bold; box-sizing:border-box;" title="Eliminar correo">✕</button>'
            '</div>',
            ((name, str(val)) for val in email_list),
        )

        return format_html(
            """
        <div id="{name}_admin_wrapper" style="width:100%; max-width:520px; box-sizing:border-box;">
            <div id="{name}_rows_container">
                {rows_rendered}
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; margin-top:8px; width:100%; box-sizing:border-box;">
                <button type="button" class="button" onclick="addAdminRow('{name}')" style="background:#417690; color:#fff; border:none; border-radius:4px; padding:7px 14px; cursor:pointer; font-weight:bold; font-size:0.85rem; display:inline-flex; align-items:center; gap:6px;">
                    ➕ Añadir otro correo
                </button>
                <span id="{name}_counter_badge" style="font-size:0.8rem; color:#94a3b8; font-weight:600; background:#1e293b; border:1px solid #334155; padding:3px 8px; border-radius:12px;">
                    1 destinatario
                </span>
            </div>
        </div>
        <script>
            function addAdminRow(fieldName) {{
                const container = document.getElementById(fieldName + '_rows_container');
                if (!container) return;
                const row = document.createElement('div');
                row.className = 'admin-email-row';
                row.style.cssText = 'display:flex; gap:8px; margin-bottom:8px; align-items:center; width:100%; max-width:520px; box-sizing:border-box;';
                row.innerHTML = `
                    <input type="email" name="${{fieldName}}" value="" class="vTextField" style="flex:1 1 auto; min-width:0; width:100%; height:34px; padding:6px 10px; border-radius:4px; box-sizing:border-box;" placeholder="destinatario@empresa.com" required>
                    <button type="button" class="button btn-remove-row" onclick="removeAdminRow(this)" style="flex:0 0 34px; width:34px; height:34px; background:#ba2121; color:#fff; border:none; border-radius:4px; padding:0; display:inline-flex; align-items:center; justify-content:center; cursor:pointer; font-size:1rem; font-weight:bold; box-sizing:border-box;" title="Eliminar correo">✕</button>
                `;
                container.appendChild(row);
                updateAdminRowControls(fieldName);
                const input = row.querySelector('input');
                if (input) input.focus();
            }}

            function removeAdminRow(btn) {{
                const row = btn.closest('.admin-email-row');
                const container = row.parentElement;
                const rows = container.getElementsByClassName('admin-email-row');
                if (rows.length > 1) {{
                    row.remove();
                    const wrapper = container.closest('[id$="_admin_wrapper"]');
                    if (wrapper) {{
                        const fieldName = wrapper.id.replace('_admin_wrapper', '');
                        updateAdminRowControls(fieldName);
                    }}
                }}
            }}

            function updateAdminRowControls(fieldName) {{
                const container = document.getElementById(fieldName + '_rows_container');
                if (!container) return;
                const rows = container.getElementsByClassName('admin-email-row');
                for (let i = 0; i < rows.length; i++) {{
                    const btn = rows[i].querySelector('.btn-remove-row');
                    if (btn) {{
                        btn.style.display = rows.length === 1 ? 'none' : 'inline-flex';
                    }}
                }}
                const badge = document.getElementById(fieldName + '_counter_badge');
                if (badge) {{
                    let filledCount = 0;
                    for (let i = 0; i < rows.length; i++) {{
                        const inp = rows[i].querySelector('input');
                        if (inp && inp.value.trim()) filledCount++;
                    }}
                    const count = filledCount > 0 ? filledCount : rows.length;
                    badge.textContent = count + ' destinatario' + (count === 1 ? '' : 's');
                }}
            }}

            window.addEmailToAdminWidget = function(fieldName, email) {{
                const container = document.getElementById(fieldName + '_rows_container');
                if (!container) return;
                const normalized = (email || '').trim().toLowerCase();
                if (!normalized) return;

                const inputs = container.querySelectorAll('input[name="' + fieldName + '"]');
                for (let i = 0; i < inputs.length; i++) {{
                    if (!inputs[i].value.trim()) {{
                        inputs[i].value = normalized;
                        updateAdminRowControls(fieldName);
                        return;
                    }}
                    if (inputs[i].value.trim().toLowerCase() === normalized) {{
                        return;
                    }}
                }}
                addAdminRow(fieldName);
                const updatedInputs = container.querySelectorAll('input[name="' + fieldName + '"]');
                const last = updatedInputs[updatedInputs.length - 1];
                if (last) last.value = normalized;
                updateAdminRowControls(fieldName);
            }};

            document.addEventListener('DOMContentLoaded', function() {{
                updateAdminRowControls('{name}');
                const container = document.getElementById('{name}_rows_container');
                if (container) {{
                    container.addEventListener('input', function(e) {{
                        if (e.target && e.target.name === '{name}') {{
                            updateAdminRowControls('{name}');
                        }}
                    }});
                }}
            }});
        </script>
        """,
            name=name,
            rows_rendered=rows_rendered,
        )

    def value_from_datadict(self, data: Any, files: Any, name: str) -> Any:
        if hasattr(data, "getlist"):
            return data.getlist(name)
        val = data.get(name)
        return [val] if val else []


class HashingFileInputWidget(forms.ClearableFileInput):
    """
    Widget de subida con detección automática instantánea del hash SHA-256 en el cliente.
    Si el archivo ya existe en el sistema, muestra un aviso inmediato con enlace para abrirlo
    y advierte proactivamente si existen destinatarios pendientes de acceder.
    """

    def render(self, name: str, value: Any, attrs: Optional[dict] = None, renderer: Any = None) -> Any:
        base_html = super().render(name, value, attrs, renderer)
        input_id = (attrs or {}).get("id", f"id_{name}")
        try:
            check_url = reverse("admin:arcamitte_encrypteddocument_check_hash")
        except Exception:
            check_url = "/admin/arcamitte/encrypteddocument/check-file-hash/"

        script_html = format_html(
            """
        <div id="{input_id}_notice_container" style="margin-top:8px;"></div>
        <script>
        (function() {{
            const input = document.getElementById("{input_id}");
            if (!input) return;
            input.addEventListener('change', async function() {{
                const container = document.getElementById("{input_id}_notice_container");
                if (!container) return;
                container.innerHTML = '';
                if (!this.files || !this.files[0]) return;
                const file = this.files[0];
                try {{
                    const buffer = await file.arrayBuffer();
                    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    
                    const resp = await fetch('{check_url}?hash=' + hashHex);
                    if (!resp.ok) return;
                    const data = await resp.json();
                    if (data.exists) {{
                        const statusBadge = data.is_consumed 
                            ? '<span style="background:#ef4444; color:#fff; padding:2px 8px; border-radius:10px; font-size:0.75rem; font-weight:bold;">🔥 Consumido</span>'
                            : '<span style="background:#10b981; color:#fff; padding:2px 8px; border-radius:10px; font-size:0.75rem; font-weight:bold;">🟢 Activo</span>';
                        const policyBadge = data.burn_policy === 'ALL_RECIPIENTS'
                            ? '<span style="background:#4338ca; color:#fff; padding:2px 8px; border-radius:10px; font-size:0.75rem; font-weight:bold;">👥 Todos</span>'
                            : '<span style="background:#0369a1; color:#fff; padding:2px 8px; border-radius:10px; font-size:0.75rem; font-weight:bold;">⚡ 1er Acceso</span>';
                        
                        let pendingWarningHtml = '';
                        if (data.pending_recipients && data.pending_recipients.length > 0) {{
                            const pendingList = data.pending_recipients.map(e => '<code style=\"background:#78350f; padding:1px 6px; border-radius:4px;\">' + e + '</code>').join(' ');
                            pendingWarningHtml = `
                                <div style="background:#451a03; border:2px solid #f59e0b; padding:10px 14px; border-radius:6px; margin:12px 0; color:#fef3c7; width:100%; max-width:100%; box-sizing:border-box; word-break:break-word;">
                                    <div style="font-weight:bold; color:#fbbf24; font-size:0.95rem; margin-bottom:4px; display:flex; align-items:center; gap:6px; flex-wrap:wrap;">
                                        <span>⚠️</span> ¡ATENCIÓN! Este documento aún no ha finalizado (accesos pendientes):
                                    </div>
                                    <div style="font-size:0.88rem; margin-bottom:8px; line-height:1.4;">
                                        Faltan por acceder: ${{pendingList}}.<br>
                                        Al reactivar con nuevos destinatarios, los anteriores pierden el acceso a menos que los vuelva a añadir a la lista.
                                    </div>
                                    <button type="button" id="${{input.id}}_btn_add_pending" class="button" style="background:#d97706; color:#fff; border:none; padding:5px 12px; border-radius:4px; font-size:0.82rem; font-weight:bold; cursor:pointer;">
                                        ➕ Volver a añadir pendientes a la lista de correos
                                    </button>
                                </div>
                            `;
                        }}

                        container.innerHTML = `
                            <div style="background:#082f49; border:1px solid #0284c7; padding:14px; border-radius:8px; color:#e0f2fe; margin-top:8px; width:100%; max-width:100%; box-sizing:border-box; word-break:break-word;">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; flex-wrap:wrap; gap:6px;">
                                    <strong style="color:#38bdf8; font-size:0.95rem;">ℹ️ Archivo ya registrado en el sistema:</strong>
                                    <div style="display:flex; gap:6px; flex-wrap:wrap;">${{policyBadge}} ${{statusBadge}}</div>
                                </div>
                                <div style="line-height:1.4;">Se localizó el registro existente para <strong>${{data.filename}}</strong> (registrado el ${{data.created_at}}).</div>
                                ${{pendingWarningHtml}}
                                <div style="margin-top:10px; display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
                                    <a href="${{data.change_url}}" class="button" style="background:#0284c7; color:#fff; padding:6px 14px; border-radius:4px; font-weight:bold; text-decoration:none; display:inline-block;">
                                        ↗️ Abrir registro existente directamente
                                    </a>
                                    <span style="font-size:0.85rem; color:#bae6fd; flex:1; min-width:220px;">
                                        O bien introduzca nuevos correos abajo y guarde: se reactivará automáticamente el registro existente conservando todo el historial.
                                    </span>
                                </div>
                            </div>
                        `;

                        if (data.pending_recipients && data.pending_recipients.length > 0) {{
                            const btn = document.getElementById(input.id + '_btn_add_pending');
                            if (btn) {{
                                btn.addEventListener('click', function() {{
                                    if (window.addEmailToAdminWidget) {{
                                        data.pending_recipients.forEach(em => window.addEmailToAdminWidget('allowed_emails', em));
                                        btn.innerText = '✓ Destinatarios pendientes añadidos';
                                        btn.style.background = '#059669';
                                        btn.disabled = true;
                                    }}
                                }});
                            }}
                        }}
                    }}
                }} catch (e) {{
                    console.log("[Arcamitte Hash Check Error]", e);
                }}
            }});
        }})();
        </script>
        """,
            input_id=input_id,
            check_url=check_url,
        )
        return format_html("{}{}", base_html, script_html)


class TargetUOWidget(forms.Select):
    """
    Widget con atajos interactivos para importar el buzón general o los miembros activos
    de la UO de destino seleccionada hacia la lista de correos autorizados.
    Permite elegir todos los miembros a la vez o seleccionar individualmente a los deseados.
    Diseñado de forma 100% responsiva para pantallas móviles y de escritorio.
    """

    def render(self, name: str, value: Any, attrs: Optional[dict] = None, renderer: Any = None) -> Any:
        base_html = super().render(name, value, attrs, renderer)
        input_id = (attrs or {}).get("id", f"id_{name}")
        helper_html = format_html(
            """
        <div id="{input_id}_helper_box" style="margin-top:10px; display:none; background:#0f172a; border:1px solid #334155; padding:12px; border-radius:6px; width:100%; max-width:680px; box-sizing:border-box; clear:both;">
            <div style="font-size:0.85rem; color:#94a3b8; margin-bottom:8px; display:flex; align-items:center; gap:6px;">
                <span>💡</span> <strong>Atajos de destinatarios de la UO de destino:</strong>
            </div>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(170px, 1fr)); gap:8px; margin-bottom:8px; width:100%; box-sizing:border-box;">
                <button type="button" id="{input_id}_btn_uo_email" class="button" style="background:#0f766e; color:#fff; border:none; padding:7px 10px; border-radius:4px; font-size:0.8rem; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:4px; text-align:center; min-height:36px; box-sizing:border-box;" title="Añadir el buzón general de la UO">
                    🏢 Buzón UO (<span id="{input_id}_uo_email_text" style="max-width:130px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:inline-block; vertical-align:bottom;"></span>)
                </button>
                <button type="button" id="{input_id}_btn_uo_members_all" class="button" style="background:#1d4ed8; color:#fff; border:none; padding:7px 10px; border-radius:4px; font-size:0.8rem; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:4px; text-align:center; min-height:36px; box-sizing:border-box;" title="Añadir todos los miembros activos a la vez">
                    👥 Todos (<span id="{input_id}_uo_members_count"></span>)
                </button>
                <button type="button" id="{input_id}_btn_toggle_members" class="button" style="background:#334155; color:#cbd5e1; border:1px solid #475569; padding:7px 10px; border-radius:4px; font-size:0.8rem; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:4px; text-align:center; min-height:36px; box-sizing:border-box;" title="Seleccionar miembros individuales">
                    👤 Miembros específicos <span id="{input_id}_arrow">▼</span>
                </button>
            </div>

            <!-- Panel desplegable interactivo para elegir miembros específicos -->
            <div id="{input_id}_specific_members_panel" style="display:none; margin-top:8px; border-top:1px solid #334155; padding-top:10px; width:100%; box-sizing:border-box;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px; margin-bottom:8px;">
                    <span style="font-size:0.82rem; color:#e2e8f0; font-weight:600;">Miembros activos de la UO:</span>
                    <div style="display:flex; gap:6px;">
                        <button type="button" id="{input_id}_btn_check_all" style="background:#1e293b; color:#38bdf8; border:1px solid #475569; padding:3px 8px; border-radius:3px; font-size:0.75rem; cursor:pointer;">Marcar todos</button>
                        <button type="button" id="{input_id}_btn_uncheck_all" style="background:#1e293b; color:#94a3b8; border:1px solid #475569; padding:3px 8px; border-radius:3px; font-size:0.75rem; cursor:pointer;">Desmarcar</button>
                    </div>
                </div>
                <div id="{input_id}_members_checklist" style="max-height:200px; overflow-y:auto; overflow-x:hidden; display:flex; flex-direction:column; gap:4px; margin-bottom:10px; padding-right:4px; width:100%; box-sizing:border-box;">
                    <!-- Lista poblada dinámicamente -->
                </div>
                <button type="button" id="{input_id}_btn_add_selected" class="button" style="width:100%; background:#2563eb; color:#fff; border:none; padding:8px 12px; border-radius:4px; font-size:0.82rem; font-weight:bold; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:6px;">
                    ➕ Añadir miembros seleccionados a la lista de correos
                </button>
            </div>
        </div>
        <script>
        (function() {{
            const select = document.getElementById("{input_id}");
            const box = document.getElementById("{input_id}_helper_box");
            const btnEmail = document.getElementById("{input_id}_btn_uo_email");
            const btnAllMembers = document.getElementById("{input_id}_btn_uo_members_all");
            const btnToggle = document.getElementById("{input_id}_btn_toggle_members");
            const panelSpecific = document.getElementById("{input_id}_specific_members_panel");
            const arrow = document.getElementById("{input_id}_arrow");
            const listContainer = document.getElementById("{input_id}_members_checklist");
            const btnCheckAll = document.getElementById("{input_id}_btn_check_all");
            const btnUncheckAll = document.getElementById("{input_id}_btn_uncheck_all");
            const btnAddSelected = document.getElementById("{input_id}_btn_add_selected");
            const txtEmail = document.getElementById("{input_id}_uo_email_text");
            const txtMembers = document.getElementById("{input_id}_uo_members_count");

            if (!select || !box) return;

            let currentData = null;

            function renderMembersChecklist(members) {{
                if (!listContainer) return;
                listContainer.innerHTML = '';
                if (!members || members.length === 0) {{
                    listContainer.innerHTML = '<div style="color:#94a3b8; font-size:0.8rem; padding:6px;">No hay miembros registrados en esta UO.</div>';
                    return;
                }}
                members.forEach((m) => {{
                    const row = document.createElement('div');
                    row.className = 'member-item-row';
                    row.style.cssText = 'display:flex !important; align-items:center !important; justify-content:space-between !important; gap:8px !important; background:#1e293b !important; padding:6px 10px !important; border-radius:4px !important; font-size:0.82rem !important; border:1px solid #334155 !important; box-sizing:border-box !important; width:100% !important; max-width:100% !important; float:none !important; margin:0 0 4px 0 !important; clear:both !important;';
                    row.innerHTML = `
                        <label style="display:flex !important; align-items:center !important; gap:8px !important; min-width:0 !important; flex:1 1 auto !important; width:auto !important; float:none !important; margin:0 !important; padding:0 !important; cursor:pointer !important; color:#f8fafc !important; font-weight:normal !important; overflow:hidden !important;">
                            <input type="checkbox" class="{input_id}_member_cb" value="${{m.email}}" checked style="cursor:pointer; flex:0 0 auto; margin:0; vertical-align:middle;">
                            <span style="font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${{m.name}}</span>
                            <span style="color:#94a3b8; font-size:0.75rem; word-break:break-all;">&lt;${{m.email}}&gt;</span>
                        </label>
                        <span style="background:#0f172a; color:#38bdf8; border:1px solid #334155; padding:2px 6px; border-radius:3px; font-size:0.7rem; font-weight:bold; flex:0 0 auto; white-space:nowrap;">${{m.role_display || m.role}}</span>
                    `;
                    listContainer.appendChild(row);
                }});
            }}

            async function onUoChange() {{
                const val = select.value;
                if (!val) {{
                    box.style.display = 'none';
                    if (panelSpecific) panelSpecific.style.display = 'none';
                    currentData = null;
                    return;
                }}
                try {{
                    const resp = await fetch('/admin/arcamitte/encrypteddocument/uo-recipients/' + val + '/');
                    if (!resp.ok) {{
                        box.style.display = 'none';
                        return;
                    }}
                    currentData = await resp.json();
                    if (currentData.uo_email) {{
                        txtEmail.textContent = currentData.uo_email;
                        btnEmail.style.display = 'inline-flex';
                    }} else {{
                        btnEmail.style.display = 'none';
                    }}
                    const count = currentData.member_emails ? currentData.member_emails.length : 0;
                    txtMembers.textContent = count + ' miembro' + (count === 1 ? '' : 's');
                    renderMembersChecklist(currentData.members || []);
                    box.style.display = 'block';
                }} catch (e) {{
                    console.log("[Arcamitte UO Recipients Error]", e);
                }}
            }}

            select.addEventListener('change', onUoChange);
            if (select.value) {{
                setTimeout(onUoChange, 100);
            }}

            if (btnEmail) {{
                btnEmail.addEventListener('click', function() {{
                    if (currentData && currentData.uo_email && window.addEmailToAdminWidget) {{
                        window.addEmailToAdminWidget('allowed_emails', currentData.uo_email);
                        const orig = btnEmail.innerText;
                        btnEmail.innerText = '✓ Buzón añadido';
                        setTimeout(() => btnEmail.innerText = orig, 2000);
                    }}
                }});
            }}

            if (btnAllMembers) {{
                btnAllMembers.addEventListener('click', function() {{
                    if (currentData && currentData.member_emails && window.addEmailToAdminWidget) {{
                        currentData.member_emails.forEach(em => window.addEmailToAdminWidget('allowed_emails', em));
                        const orig = btnAllMembers.innerText;
                        btnAllMembers.innerText = '✓ Todos añadidos';
                        setTimeout(() => btnAllMembers.innerText = orig, 2500);
                    }}
                }});
            }}

            if (btnToggle && panelSpecific) {{
                btnToggle.addEventListener('click', function() {{
                    if (panelSpecific.style.display === 'none' || !panelSpecific.style.display) {{
                        panelSpecific.style.display = 'block';
                        if (arrow) arrow.textContent = '▲';
                    }} else {{
                        panelSpecific.style.display = 'none';
                        if (arrow) arrow.textContent = '▼';
                    }}
                }});
            }}

            if (btnCheckAll) {{
                btnCheckAll.addEventListener('click', function() {{
                    document.querySelectorAll('.' + '{input_id}_member_cb').forEach(cb => cb.checked = true);
                }});
            }}

            if (btnUncheckAll) {{
                btnUncheckAll.addEventListener('click', function() {{
                    document.querySelectorAll('.' + '{input_id}_member_cb').forEach(cb => cb.checked = false);
                }});
            }}

            if (btnAddSelected) {{
                btnAddSelected.addEventListener('click', function() {{
                    if (!window.addEmailToAdminWidget) return;
                    const checkedCbs = Array.from(document.querySelectorAll('.' + '{input_id}_member_cb:checked'));
                    if (checkedCbs.length === 0) {{
                        alert('Seleccione al menos un miembro para añadir.');
                        return;
                    }}
                    checkedCbs.forEach(cb => window.addEmailToAdminWidget('allowed_emails', cb.value));
                    const orig = btnAddSelected.innerText;
                    btnAddSelected.innerText = `✓ ${{checkedCbs.length}} miembro(s) añadido(s)`;
                    btnAddSelected.style.background = '#059669';
                    setTimeout(() => {{
                        btnAddSelected.innerText = orig;
                        btnAddSelected.style.background = '#2563eb';
                    }}, 2500);
                }});
            }}
        }})();
        </script>
        """,
            input_id=input_id,
        )
        return format_html("{}{}", base_html, helper_html)


class EncryptedDocumentAddForm(forms.ModelForm):
    """
    Formulario de registro y cifrado de documentos en Django Admin.
    Cero contraseñas humanas: el sistema genera la DEK interna y cifra automáticamente.
    """

    origin_uo = forms.ModelChoiceField(
        queryset=OrganizationalUnit.objects.filter(is_active=True),
        label=_("UO Emisora"),
        required=False,
        help_text=_("Unidad Organizativa que emite y custodia el documento confidencial."),
    )
    target_uo = forms.ModelChoiceField(
        queryset=OrganizationalUnit.objects.filter(is_active=True),
        label=_("UO Receptora (Malla)"),
        required=False,
        widget=TargetUOWidget(),
        help_text=_(
            "Unidad Organizativa de destino si se trata de un trámite inter-departamental (permite auto-completar buzón y miembros)."
        ),
    )
    original_file = forms.FileField(
        label=_("Archivo confidencial original"),
        widget=HashingFileInputWidget(),
        help_text=_(
            "Formatos admitidos: PDF, LibreOffice (.odt, .ods, .odp, .odg) o Microsoft Office (.docx, .xlsx, .pptx, .doc, .xls, .ppt)."
        ),
    )
    description = forms.CharField(
        label=_("Descripción del documento"),
        required=False,
        initial="Documento confidencial tramitado a través de la pasarela segura Arcamitte.",
        widget=forms.Textarea(
            attrs={
                "rows": 3,
                "class": "vLargeTextField",
                "placeholder": _("Descripción informativa o motivo confidencial del trámite..."),
            }
        ),
        help_text=_(
            "Descripción que se incluirá en las notificaciones por correo y en la plantilla corporativa."
        ),
    )
    allowed_emails = forms.CharField(
        label=_("Correos autorizados"),
        widget=EmailListAdminWidget(),
        help_text=_("Direcciones de correo autorizadas para solicitar el canje con OTP."),
    )
    burn_policy = forms.ChoiceField(
        label=_("Política de Destrucción"),
        choices=EncryptedDocument.BurnPolicy.choices,
        initial=EncryptedDocument.BurnPolicy.FIRST_ACCESS,
        required=False,
        widget=forms.RadioSelect,
        help_text=_(
            "Seleccione si el archivo en disco debe destruirse de inmediato al primer acceso de cualquiera o conservarse hasta que todos los destinatarios autorizados lo hayan descargado."
        ),
    )
    expires_at = forms.DateTimeField(
        label=_("Fecha de caducidad"),
        required=False,
        widget=forms.DateTimeInput(
            attrs={"type": "datetime-local", "class": "form-control vDateTimeField"},
            format="%Y-%m-%dT%H:%M",
        ),
        input_formats=["%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"],
        help_text=_(
            "Fecha y hora límite de validez del asiento (por defecto, 2 semanas desde el registro). "
            "Llegada la fecha sin acceso, el asiento se cerrará automáticamente y el archivo se destruirá físicamente en disco."
        ),
    )

    class Meta:
        model = EncryptedDocument
        fields = ("origin_uo", "target_uo", "original_file", "description", "allowed_emails", "burn_policy", "expires_at")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if not self.is_bound and not self.initial.get("expires_at"):
            self.initial["expires_at"] = default_document_expiry().strftime("%Y-%m-%dT%H:%M")

    def clean(self) -> dict:
        cleaned_data = super().clean()
        origin_uo = cleaned_data.get("origin_uo")
        request_user = getattr(self, "request_user", None)
        if request_user and not request_user.is_superuser:
            if not origin_uo:
                self.add_error("origin_uo", _("Debe seleccionar una Unidad Organizativa emisora a la que pertenezca."))
            else:
                has_membership = UserUOMembership.objects.filter(
                    user=request_user, uo=origin_uo, is_active=True
                ).exists()
                if not has_membership:
                    self.add_error(
                        "origin_uo",
                        _("No dispone de membresía activa en la Unidad Organizativa seleccionada."),
                    )
        return cleaned_data

    def clean_expires_at(self) -> Optional[Any]:
        exp = self.cleaned_data.get("expires_at")
        if exp and exp <= timezone.now():
            raise forms.ValidationError(_("La fecha de caducidad debe ser posterior a la fecha y hora actual."))
        return exp

    def clean_burn_policy(self) -> str:
        return self.cleaned_data.get("burn_policy") or EncryptedDocument.BurnPolicy.FIRST_ACCESS

    def clean_original_file(self) -> Any:
        file_obj = self.cleaned_data.get("original_file")
        if not file_obj:
            raise forms.ValidationError(_("Debe seleccionar un archivo."))
        return validate_document_file(file_obj)

    def clean_allowed_emails(self) -> List[str]:
        if hasattr(self.data, "getlist"):
            raw_entries = self.data.getlist("allowed_emails")
        else:
            raw_entries = self.cleaned_data.get("allowed_emails")
        return normalize_and_validate_email_list(raw_entries)


class EncryptedDocumentChangeForm(forms.ModelForm):
    """
    Formulario de visualización y reactivación en Django Admin.
    Permite volver a subir el archivo original para re-cifrar y reactivar el documento.
    """

    target_uo = forms.ModelChoiceField(
        queryset=OrganizationalUnit.objects.filter(is_active=True),
        label=_("UO Receptora (Malla)"),
        required=False,
        widget=TargetUOWidget(),
        help_text=_(
            "Unidad Organizativa de destino si se trata de un trámite inter-departamental (permite auto-completar buzón y miembros)."
        ),
    )
    reupload_file = forms.FileField(
        label=_("Re-subir archivo original (Reactivar)"),
        required=False,
        widget=HashingFileInputWidget(),
        help_text=_(
            "Si el documento ya fue consumido o desea habilitar nuevos destinatarios, suba aquí el archivo original. Se re-cifrará y reactivará manteniendo la trazabilidad histórica."
        ),
    )
    description = forms.CharField(
        label=_("Descripción del documento"),
        required=False,
        widget=forms.Textarea(
            attrs={
                "rows": 3,
                "class": "vLargeTextField",
                "placeholder": _("Descripción informativa o motivo confidencial del trámite..."),
            }
        ),
        help_text=_(
            "Descripción que se incluirá en las notificaciones por correo y en la plantilla corporativa. Puede modificarse tanto en documentos activos como reactivados."
        ),
    )
    allowed_emails = forms.CharField(
        label=_("Correos autorizados"),
        required=True,
        widget=EmailListAdminWidget(),
        help_text=_("Destinatarios autorizados a solicitar el canje con OTP."),
    )
    burn_policy = forms.ChoiceField(
        label=_("Política de Destrucción"),
        choices=EncryptedDocument.BurnPolicy.choices,
        required=False,
        widget=forms.RadioSelect,
    )
    expires_at = forms.DateTimeField(
        label=_("Fecha de caducidad"),
        required=False,
        widget=forms.DateTimeInput(
            attrs={"type": "datetime-local", "class": "form-control vDateTimeField"},
            format="%Y-%m-%dT%H:%M",
        ),
        input_formats=["%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"],
        help_text=_(
            "Fecha y hora límite de validez del asiento. Superada la fecha sin acceso, el archivo físico se destruye en disco."
        ),
    )

    class Meta:
        model = EncryptedDocument
        fields = ("target_uo", "reupload_file", "description", "allowed_emails", "burn_policy", "expires_at")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.expires_at:
            self.initial["expires_at"] = self.instance.expires_at.strftime("%Y-%m-%dT%H:%M")

    def clean_burn_policy(self) -> str:
        return self.cleaned_data.get("burn_policy") or EncryptedDocument.BurnPolicy.FIRST_ACCESS

    def clean_reupload_file(self) -> Any:
        file_obj = self.cleaned_data.get("reupload_file")
        if file_obj:
            return validate_document_file(file_obj)
        return None

    def clean_allowed_emails(self) -> List[str]:
        if hasattr(self.data, "getlist"):
            raw_entries = self.data.getlist("allowed_emails")
        else:
            raw_entries = self.cleaned_data.get("allowed_emails")
        return normalize_and_validate_email_list(raw_entries)


class DocumentAccessLogInline(admin.TabularInline):
    """Inline de auditoría legal de accesos para el panel de administración (solo lectura)."""

    model = DocumentAccessLog
    extra = 0
    can_delete = False
    readonly_fields = ("created_at", "email", "action", "ip_address", "user_agent")
    fields = ("created_at", "email", "action", "ip_address", "user_agent")

    def has_add_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False


@admin.register(EncryptedDocument)
class EncryptedDocumentAdmin(admin.ModelAdmin):
    """
    Panel de administración para la gestión, reactivación y auditoría de documentos confidenciales.
    
    Criterios de seguridad y usabilidad:
    - Cero contraseñas humanas visibles.
    - Selector dinámico de política de destrucción (primer acceso vs todos).
    - Malla de Unidades Organizativas (UO emisora y receptora) con aislamiento estricto.
    - Detección proactiva de hash idéntico y reactivación sin pérdida de trazabilidad.
    - Botón de descarga de auditoría administrativa (Audit Bypass) preservando el archivo.
    - Botón de eliminación directa y soporte completo de borrado con destrucción segura física.
    """

    change_list_template = "admin/arcamitte/encrypteddocument_change_list.html"
    change_form_template = "admin/arcamitte/encrypteddocument_change_form.html"

    list_display = (
        "original_filename",
        "short_file_hash",
        "origin_uo_badge",
        "target_uo_badge",
        "burn_policy_badge",
        "consumption_status_badge",
        "expiry_status_badge",
        "formatted_created_at",
        "actions_column",
    )
    list_filter = ("origin_uo", "target_uo", "burn_policy", "is_consumed", "expires_at", "created_at")
    search_fields = (
        "original_filename",
        "description",
        "file_hash",
        "consumed_by",
        "origin_uo__alias",
        "origin_uo__name",
        "target_uo__alias",
        "target_uo__name",
    )
    inlines = [DocumentAccessLogInline]
    actions = ["admin_audit_download_action", "admin_terminate_document_action"]

    def get_actions(self, request: HttpRequest) -> dict:
        actions = super().get_actions(request)
        if "delete_selected" in actions:
            del actions["delete_selected"]
        return actions

    def changelist_view(self, request: HttpRequest, extra_context: Optional[dict] = None) -> HttpResponse:
        self._current_request = request
        return super().changelist_view(request, extra_context=extra_context)

    def get_list_display(self, request: HttpRequest) -> tuple:
        """Registra el request actual y retorna las columnas de visualización."""
        self._current_request = request
        return self.list_display

    def get_queryset(self, request: HttpRequest) -> models.QuerySet:
        """
        Aislamiento estricto de documentos:
        - Superusuario: Visibilidad global de toda la malla.
        - Staff con UO: Solo documentos emitidos por o destinados a sus UOs activas,
          o asientos personales creados por el propio usuario (origin_uo=None).
        """
        qs = super().get_queryset(request).select_related("origin_uo", "target_uo", "uploaded_by")
        if request.user.is_superuser:
            return qs
        user_uos = UserUOMembership.objects.filter(
            user=request.user, is_active=True
        ).values_list("uo_id", flat=True)
        return qs.filter(
            models.Q(origin_uo_id__in=user_uos)
            | models.Q(target_uo_id__in=user_uos)
            | models.Q(origin_uo_id__isnull=True, uploaded_by=request.user)
        ).distinct()

    def formfield_for_foreignkey(self, db_field: Any, request: HttpRequest, **kwargs: Any) -> Any:
        """Restringe la selección de UO emisora a las UOs en las que el usuario es miembro activo."""
        if db_field.name == "origin_uo" and not request.user.is_superuser:
            user_uos = UserUOMembership.objects.filter(
                user=request.user, is_active=True
            ).values_list("uo_id", flat=True)
            kwargs["queryset"] = OrganizationalUnit.objects.filter(id__in=user_uos, is_active=True)
        elif db_field.name in ("origin_uo", "target_uo"):
            kwargs["queryset"] = OrganizationalUnit.objects.filter(is_active=True)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def get_changeform_initial_data(self, request: HttpRequest) -> dict:
        """Pre-selecciona la UO activa principal del usuario como UO emisora por defecto."""
        initial = super().get_changeform_initial_data(request)
        if not request.user.is_superuser:
            first_membership = UserUOMembership.objects.filter(
                user=request.user, is_active=True
            ).first()
            if first_membership:
                initial.setdefault("origin_uo", first_membership.uo_id)
        return initial

    def get_form(self, request: HttpRequest, obj: Optional[EncryptedDocument] = None, **kwargs: Any) -> Any:
        base_form = EncryptedDocumentAddForm if obj is None else EncryptedDocumentChangeForm

        class FormWithUser(base_form):
            def __init__(self, *args: Any, **form_kwargs: Any) -> None:
                self.request_user = request.user
                super().__init__(*args, **form_kwargs)
                if not request.user.is_superuser and "origin_uo" in self.fields:
                    user_uos = UserUOMembership.objects.filter(
                        user=request.user, is_active=True
                    ).values_list("uo_id", flat=True)
                    self.fields["origin_uo"].queryset = OrganizationalUnit.objects.filter(
                        id__in=user_uos, is_active=True
                    )

        return FormWithUser

    def get_fieldsets(self, request: HttpRequest, obj: Optional[EncryptedDocument] = None) -> Any:
        if obj is None:
            return (
                (
                    _("Unidades Organizativas (Malla)"),
                    {
                        "fields": ("origin_uo", "target_uo"),
                        "description": _(
                            "Seleccione la UO emisora responsable del documento y, opcionalmente, la UO receptora de destino para el trámite en malla."
                        ),
                    },
                ),
                (
                    _("Registro de Documento"),
                    {
                        "fields": ("original_file", "description", "allowed_emails", "burn_policy", "expires_at"),
                        "description": _(
                            "Suba el documento original, configure la descripción informativa, los correos autorizados, la política de acceso y la fecha de caducidad del asiento (por defecto 2 semanas)."
                        ),
                    },
                ),
            )
        return (
            (
                _("Identificación del Documento"),
                {
                    "fields": (
                        "original_filename",
                        "file_hash",
                        "encrypted_file",
                        "origin_uo",
                        "target_uo",
                        "uploaded_by",
                        "corporate_email_template_panel",
                        "audit_download_panel",
                        "created_at",
                    ),
                },
            ),
            (
                _("Ciclo de Vida y Reactivación"),
                {
                    "fields": (
                        "reupload_file",
                        "description",
                        "burn_policy",
                        "expires_at",
                        "is_consumed",
                        "consumed_by",
                        "consumed_at",
                        "consumed_recipients",
                    ),
                },
            ),
            (
                _("Destinatarios Autorizados"),
                {
                    "fields": ("allowed_emails",),
                },
            ),
        )

    def get_readonly_fields(self, request: HttpRequest, obj: Optional[EncryptedDocument] = None) -> tuple:
        if obj is None:
            return ()
        return (
            "original_filename",
            "file_hash",
            "encrypted_file",
            "origin_uo",
            "uploaded_by",
            "corporate_email_template_panel",
            "audit_download_panel",
            "is_consumed",
            "consumed_by",
            "consumed_at",
            "consumed_recipients",
            "created_at",
        )

    def save_model(self, request: HttpRequest, obj: EncryptedDocument, form: Any, change: bool) -> None:
        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")

        if not change:
            original_file = form.cleaned_data["original_file"]
            description = form.cleaned_data.get("description")
            allowed_emails = form.cleaned_data["allowed_emails"]
            burn_policy = form.cleaned_data.get("burn_policy", EncryptedDocument.BurnPolicy.FIRST_ACCESS)
            origin_uo = form.cleaned_data.get("origin_uo")
            target_uo = form.cleaned_data.get("target_uo")
            expires_at = form.cleaned_data.get("expires_at")

            # Detectar si existe un documento activo previo con destinatarios pendientes (solo aplica en política ALL_RECIPIENTS)
            file_hash = calculate_file_sha256(original_file)
            existing_doc = EncryptedDocument.objects.filter(file_hash=file_hash).first()
            omitted_pending = []
            if existing_doc and not existing_doc.is_consumed and existing_doc.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
                consumed = set(existing_doc.consumed_recipients or [])
                pending = [e for e in (existing_doc.allowed_emails or []) if e not in consumed]
                omitted_pending = [e for e in pending if e not in allowed_emails]

            doc = upload_and_encrypt_document(
                original_file=original_file,
                allowed_emails=allowed_emails,
                burn_policy=burn_policy,
                description=description,
                reopen_existing=True,
                origin_uo=origin_uo,
                target_uo=target_uo,
                uploaded_by=request.user,
                admin_user=request.user,
                client_ip=client_ip,
                user_agent=user_agent,
                precalculated_hash=file_hash,
                expires_at=expires_at,
            )
            is_reactivated = getattr(doc, "_is_reactivated", False)

            obj.pk = doc.pk
            obj.id = doc.id
            obj.original_filename = doc.original_filename
            obj.description = doc.description
            obj.file_hash = doc.file_hash
            obj.encrypted_file = doc.encrypted_file
            obj.encrypted_dek = doc.encrypted_dek
            obj.allowed_emails = doc.allowed_emails
            obj.burn_policy = doc.burn_policy
            obj.origin_uo = doc.origin_uo
            obj.target_uo = doc.target_uo
            obj.uploaded_by = doc.uploaded_by
            obj.consumed_recipients = doc.consumed_recipients
            obj.is_consumed = doc.is_consumed
            obj.created_at = doc.created_at
            obj._is_reactivated = is_reactivated
            obj._omitted_pending = omitted_pending
        else:
            new_description = form.cleaned_data.get("description")
            if new_description is not None:
                obj.description = new_description

            target_uo = form.cleaned_data.get("target_uo")
            if target_uo is not None:
                obj.target_uo = target_uo

            new_expires_at = form.cleaned_data.get("expires_at")
            if new_expires_at is not None:
                obj.expires_at = new_expires_at

            reupload_file = form.cleaned_data.get("reupload_file")
            if reupload_file:
                allowed_emails = form.cleaned_data.get("allowed_emails", obj.allowed_emails)
                burn_policy = form.cleaned_data.get("burn_policy", obj.burn_policy)

                omitted_pending = []
                if not obj.is_consumed and obj.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
                    consumed = set(obj.consumed_recipients or [])
                    pending = [e for e in (obj.allowed_emails or []) if e not in consumed]
                    omitted_pending = [e for e in pending if e not in allowed_emails]

                doc = reactivate_document(
                    document=obj,
                    original_file=reupload_file,
                    new_emails=allowed_emails,
                    burn_policy=burn_policy,
                    new_description=new_description,
                    target_uo=target_uo,
                    admin_user=request.user,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    expires_at=new_expires_at,
                )
                messages.success(
                    request,
                    format_html(
                        "<strong>Documento reactivado:</strong> Se ha habilitado el acceso para {} destinatarios.",
                        len(doc.allowed_emails or []),
                    ),
                )
                if omitted_pending:
                    messages.warning(
                        request,
                        format_html(
                            "<strong>Aviso de destinatarios omitidos:</strong> Los siguientes destinatarios estaban pendientes de descargar: <strong>{}</strong>. Al no haberse incluido en la lista, no dispondrán de acceso.",
                            ", ".join(omitted_pending),
                        ),
                    )
            else:
                super().save_model(request, obj, form, change)

    def response_add(self, request: HttpRequest, obj: EncryptedDocument, post_url_continue: Optional[str] = None) -> HttpResponse:
        if getattr(obj, "_is_reactivated", False):
            messages.info(
                request,
                format_html(
                    "<strong>Documento reactivado (Identificador: {})</strong><br><br>"
                    "Se ha detectado un registro existente para este archivo y se ha actualizado en el sistema.<br>"
                    "Total de destinatarios habilitados: <strong>{}</strong>.<br>"
                    "<em>Se conserva el historial de accesos y auditoría.</em>",
                    obj.file_hash[:16],
                    len(obj.allowed_emails or []),
                ),
            )
            if getattr(obj, "_omitted_pending", None):
                messages.warning(
                    request,
                    format_html(
                        "<strong>Aviso de destinatarios omitidos:</strong> Los destinatarios pendientes de acceder: <strong>{}</strong> no fueron reincorporados a la lista.",
                        ", ".join(obj._omitted_pending),
                    ),
                )
        else:
            messages.success(
                request,
                format_html(
                    "<strong>Documento registrado correctamente.</strong><br>"
                    "Identificador SHA-256 (Localizador de descarga):<br>"
                    "<code style='background:#1e293b; color:#38bdf8; padding:4px 8px; border-radius:4px; font-weight:bold; font-size:1rem; user-select:all; word-break:break-all; display:inline-block; max-width:100%;'>{}</code><br><br>"
                    "<em>Facilite este identificador al destinatario para que pueda tramitar la descarga.</em>",
                    obj.file_hash,
                ),
            )
        return super().response_add(request, obj, post_url_continue)

    def delete_model(self, request: HttpRequest, obj: EncryptedDocument) -> None:
        raise PermissionDenied(
            _("Los asientos documentales son inmutables. Utilice la función de finalización de asiento con constancia de vicisitud.")
        )

    def delete_queryset(self, request: HttpRequest, queryset: Any) -> None:
        raise PermissionDenied(
            _("Los asientos documentales son inmutables. Utilice la acción masiva de finalización de asientos.")
        )

    def has_delete_permission(self, request: HttpRequest, obj: Optional[EncryptedDocument] = None) -> bool:
        """Los asientos documentales son estrictamente inmutables. Se prohíbe el borrado directo."""
        return False

    def get_urls(self) -> List[Any]:
        urls = super().get_urls()
        custom_urls = [
            path(
                "check-file-hash/",
                self.admin_site.admin_view(self.check_file_hash_view),
                name="arcamitte_encrypteddocument_check_hash",
            ),
            path(
                "uo-recipients/<int:uo_id>/",
                self.admin_site.admin_view(self.uo_recipients_view),
                name="arcamitte_encrypteddocument_uo_recipients",
            ),
            path(
                "<path:object_id>/audit-download/",
                self.admin_site.admin_view(self.audit_download_view),
                name="arcamitte_encrypteddocument_audit_download",
            ),
            path(
                "<path:object_id>/terminate/",
                self.admin_site.admin_view(self.terminate_document_view),
                name="arcamitte_encrypteddocument_terminate",
            ),
        ]
        return custom_urls + urls

    def uo_recipients_view(self, request: HttpRequest, uo_id: int) -> JsonResponse:
        """Endpoint JSON para obtener buzón y correos de miembros de una UO para auto-completado."""
        try:
            uo = OrganizationalUnit.objects.get(pk=uo_id, is_active=True)
        except OrganizationalUnit.DoesNotExist:
            return JsonResponse({"error": "UO no encontrada"}, status=404)

        memberships = (
            UserUOMembership.objects.filter(uo=uo, is_active=True, user__is_active=True)
            .exclude(user__email="")
            .select_related("user")
            .order_by("user__first_name", "user__last_name", "user__username")
        )

        members_list = []
        member_emails = []
        for m in memberships:
            em = m.user.email.strip().lower()
            if em and em not in member_emails:
                member_emails.append(em)
                full_name = f"{m.user.first_name} {m.user.last_name}".strip()
                display_name = full_name or m.user.username
                members_list.append({
                    "username": m.user.username,
                    "name": display_name,
                    "email": em,
                    "role": m.role,
                    "role_display": str(m.get_role_display()),
                })

        return JsonResponse({
            "uo_alias": uo.alias,
            "uo_name": uo.name,
            "uo_email": uo.email or "",
            "member_emails": member_emails,
            "members": members_list,
        })

    def check_file_hash_view(self, request: HttpRequest) -> JsonResponse:
        """Endpoint AJAX para verificar hash en cliente antes de subir."""
        file_hash = (request.GET.get("hash") or "").strip().lower()
        if not file_hash:
            return JsonResponse({"exists": False})

        doc = EncryptedDocument.objects.filter(file_hash=file_hash).first()
        if not doc:
            return JsonResponse({"exists": False})

        # Destinatarios pendientes únicamente aplican si la política es ALL_RECIPIENTS y no está consumido
        pending = []
        if not doc.is_consumed and doc.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
            consumed_set = set(doc.consumed_recipients or [])
            pending = [e for e in (doc.allowed_emails or []) if e not in consumed_set]

        change_url = reverse("admin:arcamitte_encrypteddocument_change", args=[doc.pk])

        return JsonResponse({
            "exists": True,
            "filename": doc.original_filename,
            "description": doc.description,
            "is_consumed": doc.is_consumed,
            "burn_policy": doc.burn_policy,
            "burn_policy_display": str(doc.get_burn_policy_display()),
            "pending_recipients": pending,
            "created_at": doc.created_at.strftime("%Y-%m-%d %H:%M") if doc.created_at else "",
            "change_url": change_url,
        })

    def audit_download_view(self, request: HttpRequest, object_id: str) -> HttpResponse:
        """Vista de descarga de auditoría administrativa para staff autorizado."""
        if not (request.user.is_superuser or request.user.has_perm("arcamitte.can_audit_download")):
            raise PermissionDenied(_("No cuenta con permisos para realizar descargas de auditoría administrativa."))

        doc = self.get_object(request, object_id)
        if not doc:
            raise Http404(_("Documento no encontrado."))

        if doc.is_consumed:
            messages.error(
                request,
                _("El documento ya fue entregado y no se encuentra disponible en la pasarela."),
            )
            return HttpResponseRedirect(reverse("admin:arcamitte_encrypteddocument_change", args=[object_id]))

        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")

        success, decrypted_bytes, original_filename, message = admin_decrypt_document(
            document=doc,
            admin_user=request.user,
            client_ip=client_ip,
            user_agent=user_agent,
        )

        if not success:
            messages.error(request, message)
            return HttpResponseRedirect(reverse("admin:arcamitte_encrypteddocument_change", args=[object_id]))

        safe_name = sanitize_content_disposition_filename(original_filename)
        response = FileResponse(
            io.BytesIO(decrypted_bytes),
            as_attachment=True,
            filename=f"AUDIT_{safe_name}",
        )
        return apply_no_store_headers(response)

    def terminate_document_view(self, request: HttpRequest, object_id: str) -> HttpResponse:
        """
        Vista de confirmación y ejecución de finalización de asiento.
        Sustituye la eliminación física por la trituración del archivo y constancia de vicisitud.
        """
        doc = self.get_object(request, object_id)
        if not doc:
            raise Http404(_("Documento no encontrado."))

        if not request.user.is_superuser:
            user_uos = UserUOMembership.objects.filter(
                user=request.user, is_active=True
            ).values_list("uo_id", flat=True)
            if doc.origin_uo_id not in user_uos and doc.target_uo_id not in user_uos:
                raise PermissionDenied(_("No tiene permisos para gestionar este asiento documental."))

        if doc.is_consumed:
            messages.info(
                request,
                _("Este asiento ya se encuentra finalizado y su archivo físico ha sido retirado."),
            )
            return HttpResponseRedirect(reverse("admin:arcamitte_encrypteddocument_changelist"))

        if request.method == "POST":
            reason = (request.POST.get("reason") or "").strip()
            client_ip = get_client_ip(request)
            user_agent = request.META.get("HTTP_USER_AGENT")

            success, msg = terminate_document_manually(
                document=doc,
                admin_user=request.user,
                client_ip=client_ip,
                user_agent=user_agent,
                reason=reason,
            )
            if success:
                messages.success(request, msg)
            else:
                messages.warning(request, msg)
            return HttpResponseRedirect(reverse("admin:arcamitte_encrypteddocument_changelist"))

        context = {
            **self.admin_site.each_context(request),
            "title": _("Finalizar Asiento Documental (Constancia de Vicisitud)"),
            "object": doc,
            "opts": self.model._meta,
        }
        return render(request, "admin/arcamitte/terminate_confirmation.html", context)

    @admin.action(description=_("⏹️ Finalizar asientos seleccionados (triturar archivo y dejar vicisitud)"))
    def admin_terminate_document_action(self, request: HttpRequest, queryset: Any) -> None:
        count = 0
        client_ip = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT")
        for doc in queryset:
            if not doc.is_consumed:
                if not request.user.is_superuser:
                    user_uos = UserUOMembership.objects.filter(
                        user=request.user, is_active=True
                    ).values_list("uo_id", flat=True)
                    if doc.origin_uo_id not in user_uos and doc.target_uo_id not in user_uos:
                        continue
                success, _ = terminate_document_manually(
                    document=doc,
                    admin_user=request.user,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    reason="Finalización masiva desde Django Admin",
                )
                if success:
                    count += 1
        self.message_user(
            request,
            format_html(
                "<strong>Finalización completada:</strong> Se han finalizado {} asiento(s), destruyendo sus archivos físicos en disco y registrando la vicisitud en la auditoría legal.",
                count,
            ),
            level=messages.SUCCESS,
        )

    @admin.action(description=_("Descarga de auditoría administrativa"))
    def admin_audit_download_action(self, request: HttpRequest, queryset: Any) -> Optional[HttpResponse]:
        if not (request.user.is_superuser or request.user.has_perm("arcamitte.can_audit_download")):
            raise PermissionDenied(_("No cuenta con permisos de auditoría."))

        count = queryset.count()
        if count != 1:
            self.message_user(
                request,
                _("Por motivos de seguridad, la descarga de auditoría debe realizarse de forma individual por documento."),
                level=messages.WARNING,
            )
            return None

        doc = queryset.first()
        download_url = reverse("admin:arcamitte_encrypteddocument_audit_download", args=[doc.pk])
        return HttpResponseRedirect(download_url)

    @admin.display(description=_("UO Emisora"), ordering="origin_uo__alias")
    def origin_uo_badge(self, obj: EncryptedDocument) -> str:
        if obj.origin_uo:
            return format_html(
                '<span style="background:#0f172a; color:#38bdf8; border:1px solid #0284c7; padding:2px 8px; border-radius:6px; font-weight:bold; font-size:0.75rem; white-space:nowrap;" title="[{}] {}">[{}] {}</span>',
                obj.origin_uo.numeric_code,
                obj.origin_uo.name,
                obj.origin_uo.numeric_code,
                obj.origin_uo.alias,
            )
        return format_html('<span style="color:#64748b;">{}</span>', "—")

    @admin.display(description=_("UO Receptora"), ordering="target_uo__alias")
    def target_uo_badge(self, obj: EncryptedDocument) -> str:
        if obj.target_uo:
            return format_html(
                '<span style="background:#1e1b4b; color:#a5b4fc; border:1px solid #6366f1; padding:2px 8px; border-radius:6px; font-weight:bold; font-size:0.75rem; white-space:nowrap;" title="[{}] {}">[{}] {}</span>',
                obj.target_uo.numeric_code,
                obj.target_uo.name,
                obj.target_uo.numeric_code,
                obj.target_uo.alias,
            )
        return format_html('<span style="color:#64748b;">{}</span>', "—")

    @admin.display(description=_("Hash SHA-256"))
    def short_file_hash(self, obj: EncryptedDocument) -> str:
        return format_html(
            '<code style="background:#0f172a; color:#38bdf8; padding:2px 6px; border-radius:4px; font-family:monospace; font-size:0.75rem; white-space:nowrap;" title="{}">{}...{}</code>',
            obj.file_hash,
            obj.file_hash[:8],
            obj.file_hash[-6:],
        )

    @admin.display(description=_("Política"))
    def burn_policy_badge(self, obj: EncryptedDocument) -> str:
        if obj.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
            return format_html(
                '<span style="background:#1e1b4b; color:#c7d2fe; border:1px solid #6366f1; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem; white-space:nowrap;" title="{}">{}</span>',
                "Disponible para todos los destinatarios autorizados",
                "👥 Todos",
            )
        return format_html(
            '<span style="background:#18181b; color:#e4e4e7; border:1px solid #71717a; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem; white-space:nowrap;" title="{}">{}</span>',
            "Disponible para un único acceso (primer acceso)",
            "⚡ 1er Acceso",
        )

    @admin.display(description=_("Estado"))
    def consumption_status_badge(self, obj: EncryptedDocument) -> str:
        if obj.is_consumed:
            time_str = obj.consumed_at.strftime("%Y-%m-%d %H:%M UTC") if obj.consumed_at else ""
            consumed_by_str = obj.consumed_by or str(_("desconocido"))
            return format_html(
                '<span style="background:#450a0a; color:#f87171; border:1px solid #ef4444; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem; white-space:nowrap;" title="Retirado el {} por {}">🔥 Retirado ({})</span>',
                time_str,
                consumed_by_str,
                consumed_by_str,
            )
        if obj.burn_policy == EncryptedDocument.BurnPolicy.ALL_RECIPIENTS:
            total = len(obj.allowed_emails or [])
            consumed = len(obj.consumed_recipients or [])
            return format_html(
                '<span style="background:#082f49; color:#38bdf8; border:1px solid #0284c7; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem; white-space:nowrap;" title="Descargado por {consumed}/{total} destinatarios">🟢 Disponible ({consumed}/{total} descargados)</span>',
                consumed=consumed,
                total=total,
            )
        return format_html(
            '<span style="background:#022c22; color:#34d399; border:1px solid #10b981; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem; white-space:nowrap;">{}</span>',
            "🟢 Disponible para descarga",
        )

    @admin.display(description=_("Fecha"), ordering="created_at")
    def formatted_created_at(self, obj: EncryptedDocument) -> str:
        if not obj.created_at:
            return format_html('<span style="color:#64748b;">{}</span>', "—")
        return format_html(
            '<span style="font-size:0.75rem; color:#94a3b8; white-space:nowrap;">{}</span>',
            obj.created_at.strftime("%Y-%m-%d %H:%M"),
        )

    @admin.display(description=_("Caducidad"), ordering="expires_at")
    def expiry_status_badge(self, obj: EncryptedDocument) -> str:
        if not obj.expires_at:
            return format_html('<span style="color:#64748b;">{}</span>', "—")
        now = timezone.now()
        if obj.is_consumed:
            return format_html(
                '<span style="color:#64748b; font-size:0.75rem;" title="Caducaba: {}">⏹️ Finalizado</span>',
                obj.expires_at.strftime("%Y-%m-%d %H:%M"),
            )
        if now >= obj.expires_at:
            return format_html(
                '<span style="background:#450a0a; color:#f87171; border:1px solid #ef4444; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem; white-space:nowrap;" title="Caducó el {}">⛔ Vencido</span>',
                obj.expires_at.strftime("%Y-%m-%d %H:%M"),
            )
        diff = obj.expires_at - now
        days = diff.days
        hours = diff.seconds // 3600
        if days > 1:
            time_str = f"{days} días"
            bg = "#0f172a"
            color = "#38bdf8"
            border = "#0284c7"
        elif days == 1:
            time_str = f"1 día {hours}h"
            bg = "#1e1b4b"
            color = "#a5b4fc"
            border = "#6366f1"
        else:
            time_str = f"{hours}h restantes"
            bg = "#451a03"
            color = "#fb923c"
            border = "#f97316"

        return format_html(
            '<span style="background:{}; color:{}; border:1px solid {}; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.75rem; white-space:nowrap;" title="Caduca el {}">⏳ {}</span>',
            bg,
            color,
            border,
            obj.expires_at.strftime("%Y-%m-%d %H:%M"),
            time_str,
        )

    @admin.display(description=_("Acciones"))
    def actions_column(self, obj: EncryptedDocument) -> str:
        """Columna consolidada de acciones responsive según permisos activos."""
        req = getattr(self, "_current_request", None)
        can_audit = (req is None) or req.user.is_superuser or req.user.has_perm("arcamitte.can_audit_download")

        buttons = [self.corporate_email_button(obj)]
        if can_audit:
            buttons.append(self.audit_download_button(obj))
        if not obj.is_consumed:
            buttons.append(self.terminate_action_button(obj))

        return format_html(
            '<div style="display:inline-flex; gap:6px; align-items:center; flex-wrap:nowrap;">{}</div>',
            format_html_join(" ", "{}", ((b,) for b in buttons)),
        )

    @admin.display(description=_("Plantilla Correo"))
    def corporate_email_button(self, obj: EncryptedDocument) -> str:
        """Botón interactivo en la lista para copiar el texto de notificación con hash y nombre de archivo."""
        text = generate_corporate_email_text(obj)
        escaped_json = json.dumps(text)
        return format_html(
            '<button type="button" class="button" style="background:#0f766e; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:0.78rem; cursor:pointer; border:none; display:inline-flex; align-items:center; gap:3px; white-space:nowrap;" '
            'onclick=\'navigator.clipboard.writeText({text_json}).then(() => {{ const orig = this.innerHTML; this.innerHTML="✓ ¡Copiado!"; this.style.background="#059669"; setTimeout(() => {{ this.innerHTML=orig; this.style.background="#0f766e"; }}, 2500); }}).catch(() => prompt("Copie el texto para el correo:", {text_json}));\' '
            'title="Copiar plantilla de notificación para enviar por correo al destinatario">'
            '📋 Plantilla'
            '</button>',
            text_json=escaped_json,
        )

    @admin.display(description=_("Auditoría"))
    def audit_download_button(self, obj: EncryptedDocument) -> str:
        """Botón interactivo en la lista de documentos para descarga de auditoría."""
        if obj.is_consumed:
            return format_html(
                '<span style="background:#7f1d1d; color:#fca5a5; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:0.78rem; white-space:nowrap;" title="{}">{}</span>',
                "Documento consumido y retirado",
                "🛡️ Retirado",
            )
        download_url = reverse("admin:arcamitte_encrypteddocument_audit_download", args=[obj.pk])
        return format_html(
            '<a href="{}" class="button" style="background:#0284c7; color:#fff; padding:3px 8px; border-radius:4px; text-decoration:none; font-weight:bold; font-size:0.78rem; display:inline-flex; align-items:center; gap:3px; white-space:nowrap;" title="Descarga de auditoría administrativa">'
            '🛡️ Auditoría'
            '</a>',
            download_url,
        )

    @admin.display(description=_("Finalizar Asiento"))
    def terminate_action_button(self, obj: EncryptedDocument) -> str:
        """Botón directo de finalización deliberada de asiento con trituración física y constancia de vicisitud."""
        if obj.is_consumed:
            return format_html('<span style="color:#64748b; font-size:0.78rem;">{}</span>', "⏹️ Finalizado")
        url = reverse("admin:arcamitte_encrypteddocument_terminate", args=[obj.pk])
        return format_html(
            '<a class="button" href="{}" style="background-color:#991b1b; color:white; padding:3px 8px; border-radius:4px; text-decoration:none; font-size:0.78rem; font-weight:bold; display:inline-flex; align-items:center; gap:2px; white-space:nowrap;" title="Finalizar asiento y destruir archivo físico">⏹️ Finalizar</a>',
            url,
        )

    def corporate_email_template_panel(self, obj: EncryptedDocument) -> str:
        """Panel con texto formal prediseñado listo para copiar o abrir en cliente de correo."""
        text = generate_corporate_email_text(obj)
        escaped_json = json.dumps(text)
        destinatarios = ", ".join(obj.allowed_emails or [])
        mailto_subject = quote(f"Documento disponible para su descarga: {obj.original_filename}")
        mailto_body = quote(text)
        mailto_link = f"mailto:{destinatarios}?subject={mailto_subject}&body={mailto_body}"

        return format_html(
            '<div style="background:#0f172a; border:1px solid #334155; padding:14px; border-radius:8px; margin-bottom:15px; color:#e2e8f0; width:100%; max-width:100%; box-sizing:border-box;">'
            '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; flex-wrap:wrap; gap:8px;">'
            '<strong style="color:#38bdf8; font-size:0.95rem;">Plantilla de Notificación por Correo Electrónico:</strong>'
            '<div style="display:flex; gap:8px; flex-wrap:wrap;">'
            '<button type="button" class="button" style="background:#0284c7; color:#fff; padding:5px 12px; border-radius:4px; font-weight:bold; font-size:0.82rem; cursor:pointer; border:none; display:inline-flex; align-items:center; gap:4px;" '
            'onclick=\'navigator.clipboard.writeText({text_json}).then(() => {{ const orig = this.innerHTML; this.innerHTML="✓ ¡Texto copiado!"; this.style.background="#059669"; setTimeout(() => {{ this.innerHTML=orig; this.style.background="#0284c7"; }}, 2500); }}).catch(() => prompt("Copie el texto para el correo:", {text_json}));\'>'
            'Copiar texto'
            '</button>'
            '<a href="{mailto_link}" class="button" style="background:#475569; color:#fff; padding:5px 12px; border-radius:4px; font-weight:bold; font-size:0.82rem; text-decoration:none; display:inline-flex; align-items:center; gap:4px;" title="Abrir en cliente de correo local">'
            'Abrir en cliente de correo'
            '</a>'
            '</div>'
            '</div>'
            '<div style="font-size:0.82rem; color:#94a3b8; margin-bottom:8px;">'
            'Utilice este texto formal para notificar a los destinatarios. Incluye el identificador (SHA-256), nombre del archivo, descripción e instrucciones de descarga.'
            '</div>'
            '<textarea readonly rows="9" style="width:100%; box-sizing:border-box; background:#1e293b; color:#f1f5f9; border:1px solid #475569; border-radius:6px; font-family:monospace; font-size:0.85rem; padding:10px; line-height:1.45; resize:vertical;" id="corporate_email_textarea">{text}</textarea>'
            '</div>',
            text=text,
            text_json=escaped_json,
            mailto_link=mailto_link,
        )

    def audit_download_panel(self, obj: EncryptedDocument) -> str:
        """Panel de herramientas de auditoría en la vista detallada del documento."""
        if obj.is_consumed:
            return format_html(
                '<div style="background:#450a0a; border:1px solid #dc2626; color:#fecaca; padding:10px; border-radius:6px;">'
                '<strong>{}</strong> {}'
                '</div>',
                "Documento ya entregado:",
                "El documento ya ha sido retirado de la pasarela y no se encuentra disponible para descargas de auditoría.",
            )
        download_url = reverse("admin:arcamitte_encrypteddocument_audit_download", args=[obj.pk])
        return format_html(
            '<div style="background:#082f49; border:1px solid #0284c7; padding:12px; border-radius:6px; color:#e0f2fe;">'
            '<strong style="color:#38bdf8;">Descarga de Auditoría Administrativa:</strong><br>'
            '<span style="font-size:0.85rem; color:#bae6fd;">Permite al personal autorizado inspeccionar el archivo original descifrado sin afectar a la disponibilidad para los destinatarios.</span><br><br>'
            '<a href="{}" class="button" style="background:#0284c7; color:#fff; padding:6px 14px; border-radius:4px; font-weight:bold; text-decoration:none; display:inline-block;">'
            'Descargar copia de auditoría'
            '</a>'
            '</div>',
            download_url,
        )


class OrganizationalUnitBatchImportForm(forms.Form):
    """Formulario para la carga masiva e idempotente de UOs y Usuarios vía JSON."""

    json_file = forms.FileField(
        label=_("Archivo JSON de aprovisionamiento"),
        help_text=_(
            "Archivo con extensión .json que contenga las definiciones de 'organizational_units' y 'users' según el esquema oficial."
        ),
    )

    def clean_json_file(self) -> Any:
        f = self.cleaned_data.get("json_file")
        if not f:
            raise forms.ValidationError(_("Debe adjuntar un archivo JSON."))
        if not f.name.lower().endswith(".json"):
            raise forms.ValidationError(_("El archivo debe tener extensión .json."))
        return f


class UserUOMembershipInlineForUO(admin.TabularInline):
    """Gestión de miembros de usuarios asignados a una UO."""

    model = UserUOMembership
    extra = 1
    fields = ("user", "role", "is_active")


@admin.register(OrganizationalUnit)
class OrganizationalUnitAdmin(admin.ModelAdmin):
    """
    Panel de administración para la gestión de Unidades Organizativas (UO).
    Soporta carga masiva JSON restringida al Rol Maestro (superuser).
    """

    change_list_template = "admin/arcamitte/organizationalunit_change_list.html"
    list_display = (
        "numeric_code",
        "alias",
        "name",
        "email",
        "active_members_badge",
        "is_active",
        "created_at",
    )
    list_filter = ("is_active", "created_at")
    search_fields = ("numeric_code", "alias", "name", "email")
    inlines = [UserUOMembershipInlineForUO]

    @admin.display(description=_("Miembros activos"))
    def active_members_badge(self, obj: OrganizationalUnit) -> str:
        count = obj.memberships.filter(is_active=True).count()
        return format_html(
            '<span style="background:#0f766e; color:#fff; padding:2px 8px; border-radius:10px; font-weight:bold; font-size:0.8rem;">{} miembros</span>',
            count,
        )

    def get_queryset(self, request: HttpRequest) -> models.QuerySet:
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        user_uos = UserUOMembership.objects.filter(
            user=request.user, is_active=True
        ).values_list("uo_id", flat=True)
        return qs.filter(id__in=user_uos)

    def has_add_permission(self, request: HttpRequest) -> bool:
        return request.user.is_superuser

    def has_delete_permission(self, request: HttpRequest, obj: Optional[OrganizationalUnit] = None) -> bool:
        return request.user.is_superuser

    def has_change_permission(self, request: HttpRequest, obj: Optional[OrganizationalUnit] = None) -> bool:
        if request.user.is_superuser:
            return True
        if obj is None:
            return True
        return UserUOMembership.objects.filter(
            user=request.user, uo=obj, role=UserUOMembership.Role.ADMIN, is_active=True
        ).exists()

    def get_urls(self) -> List[Any]:
        urls = super().get_urls()
        custom_urls = [
            path(
                "import-batch/",
                self.admin_site.admin_view(self.import_batch_view),
                name="arcamitte_organizationalunit_import_batch",
            ),
        ]
        return custom_urls + urls

    def import_batch_view(self, request: HttpRequest) -> HttpResponse:
        if not request.user.is_superuser:
            raise PermissionDenied(
                _("Solo el Rol Maestro (Superusuario) puede realizar cargas masivas de UOs y Usuarios.")
            )

        if request.method == "POST":
            form = OrganizationalUnitBatchImportForm(request.POST, request.FILES)
            if form.is_valid():
                uploaded_file = form.cleaned_data["json_file"]
                try:
                    content = uploaded_file.read().decode("utf-8")
                    data = json.loads(content)
                    uos_count, users_count, notes = process_batch_import_json(data)
                    notes_display = notes[:15]
                    notes_formatted = format_html_join("<br>", "{}", ((n,) for n in notes_display))
                    if len(notes) > 15:
                        notes_formatted = format_html("{}...", notes_formatted)
                    msg = format_html(
                        "<strong>Carga masiva completada:</strong> Se procesaron {} UOs y {} usuarios vinculados.<br>{}",
                        uos_count,
                        users_count,
                        notes_formatted,
                    )
                    messages.success(request, msg)
                    return HttpResponseRedirect(reverse("admin:arcamitte_organizationalunit_changelist"))
                except json.JSONDecodeError as exc:
                    messages.error(request, format_html("<strong>Error de sintaxis JSON:</strong> {}", exc))
                except forms.ValidationError as exc:
                    messages.error(
                        request,
                        format_html(
                            "<strong>Error de validación:</strong> {}",
                            exc.message if hasattr(exc, "message") else exc,
                        ),
                    )
                except Exception as exc:
                    messages.error(request, format_html("<strong>Error en la importación masiva:</strong> {}", exc))
        else:
            form = OrganizationalUnitBatchImportForm()

        context = {
            **self.admin_site.each_context(request),
            "title": _("Carga Masiva de Unidades Organizativas y Usuarios (JSON)"),
            "form": form,
            "opts": self.model._meta,
        }
        return render(request, "admin/arcamitte/import_batch.html", context)


@admin.register(AccessVerificationToken)
class AccessVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ("created_at", "email", "document", "is_used", "failed_attempts", "expires_at")
    list_filter = ("is_used", "created_at")
    search_fields = ("email", "document__file_hash", "document__original_filename")
    readonly_fields = ("document", "email", "otp_code", "created_at", "expires_at", "is_used", "failed_attempts")

    def get_queryset(self, request: HttpRequest) -> models.QuerySet:
        qs = super().get_queryset(request).select_related("document__origin_uo", "document__target_uo")
        if request.user.is_superuser:
            return qs
        user_uos = UserUOMembership.objects.filter(
            user=request.user, is_active=True
        ).values_list("uo_id", flat=True)
        return qs.filter(
            models.Q(document__origin_uo_id__in=user_uos)
            | models.Q(document__target_uo_id__in=user_uos)
            | models.Q(document__origin_uo_id__isnull=True, document__uploaded_by=request.user)
        ).distinct()

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False

    def get_actions(self, request: HttpRequest) -> dict:
        actions = super().get_actions(request)
        if "delete_selected" in actions:
            del actions["delete_selected"]
        return actions


@admin.register(DocumentAccessLog)
class DocumentAccessLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "email", "action", "origin_uo", "target_uo", "document", "ip_address", "details")
    list_filter = ("action", "origin_uo", "target_uo", "created_at")
    search_fields = ("email", "ip_address", "document__file_hash", "document__original_filename", "details")
    readonly_fields = (
        "document",
        "email",
        "action",
        "origin_uo",
        "target_uo",
        "ip_address",
        "user_agent",
        "details",
        "created_at",
    )

    def get_queryset(self, request: HttpRequest) -> models.QuerySet:
        qs = super().get_queryset(request).select_related("origin_uo", "target_uo", "document")
        if request.user.is_superuser:
            return qs
        user_uos = UserUOMembership.objects.filter(
            user=request.user, is_active=True
        ).values_list("uo_id", flat=True)
        return qs.filter(
            models.Q(origin_uo_id__in=user_uos)
            | models.Q(target_uo_id__in=user_uos)
            | models.Q(origin_uo_id__isnull=True, document__uploaded_by=request.user)
        ).distinct()

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Optional[Any] = None) -> bool:
        """Garantía de inmutabilidad: los registros de auditoría no pueden eliminarse."""
        return False

    def get_actions(self, request: HttpRequest) -> dict:
        actions = super().get_actions(request)
        if "delete_selected" in actions:
            del actions["delete_selected"]
        return actions


class UserUOMembershipInlineForUser(admin.TabularInline):
    """Gestión de membresías de UO desde la ficha del usuario en Django Auth."""

    model = UserUOMembership
    extra = 1
    fields = ("uo", "role", "is_active")


User = get_user_model()
try:
    admin.site.unregister(User)
except admin.sites.NotRegistered:
    pass


@admin.register(User)
class CustomUserAdmin(BaseUserAdmin):
    inlines = list(BaseUserAdmin.inlines) + [UserUOMembershipInlineForUser]
