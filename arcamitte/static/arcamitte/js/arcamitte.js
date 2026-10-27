/**
 * ARCAMITTE - Motor Interactivo Tailwind / Shadcn UI + Tom Select + HTMX
 */

/**
 * Normaliza texto para comparación insensible a mayúsculas y tildes.
 */
function arcaNormalizeText(str) {
  return (str || "")
    .toString()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim();
}

/**
 * Controlador ligero de Modales, Dropdowns, Alertas y Collapse (Sustituto nativo de Bootstrap JS)
 */
(function initTailwindDialogShim() {
  class ArcaModal {
    constructor(el) {
      this.el = el;
    }
    show() {
      if (!this.el) return;
      this.el.classList.add("show");
      this.el.style.display = "flex";
      this.el.removeAttribute("aria-hidden");
      this.el.setAttribute("aria-modal", "true");
      document.body.classList.add("modal-open");
      this.el.dispatchEvent(new CustomEvent("shown.bs.modal", { bubbles: true }));
    }
    hide() {
      if (!this.el) return;
      this.el.classList.remove("show");
      this.el.style.display = "none";
      this.el.setAttribute("aria-hidden", "true");
      this.el.removeAttribute("aria-modal");
      document.querySelectorAll(".modal-backdrop").forEach(function (bd) {
        bd.remove();
      });
      document.body.classList.remove("modal-open");
      document.body.style.removeProperty("overflow");
      document.body.style.removeProperty("padding-right");
      this.el.dispatchEvent(new CustomEvent("hidden.bs.modal", { bubbles: true }));
    }
    static getOrCreateInstance(el) {
      if (!el) return new ArcaModal(null);
      if (!el._arcaModalInstance) {
        el._arcaModalInstance = new ArcaModal(el);
      }
      return el._arcaModalInstance;
    }
    static getInstance(el) {
      return el ? el._arcaModalInstance || new ArcaModal(el) : null;
    }
  }

  // Exponer shim compatible para código que invoque bootstrap.Modal
  window.bootstrap = window.bootstrap || {};
  window.bootstrap.Modal = ArcaModal;

  // Delegación global de clics para Modales, Dropdowns, Alertas y Collapse
  document.addEventListener("click", function (e) {
    // 1. Abrir Modal: [data-bs-toggle="modal"]
    const modalTrigger = e.target.closest("[data-bs-toggle='modal']");
    if (modalTrigger) {
      e.preventDefault();
      const targetSel =
        modalTrigger.getAttribute("data-bs-target") || modalTrigger.getAttribute("href");
      if (targetSel) {
        const modalEl = document.querySelector(targetSel);
        if (modalEl) ArcaModal.getOrCreateInstance(modalEl).show();
      }
      return;
    }

    // 2. Cerrar Modal: [data-bs-dismiss="modal"] o clic en el fondo oscuro (.modal)
    const modalDismiss = e.target.closest("[data-bs-dismiss='modal']");
    if (modalDismiss) {
      e.preventDefault();
      const modalEl = modalDismiss.closest(".modal");
      if (modalEl) ArcaModal.getOrCreateInstance(modalEl).hide();
      return;
    }
    if (e.target.classList && e.target.classList.contains("modal") && e.target.classList.contains("show")) {
      ArcaModal.getOrCreateInstance(e.target).hide();
      return;
    }

    // 3. Cerrar Alerta: [data-bs-dismiss="alert"]
    const alertDismiss = e.target.closest("[data-bs-dismiss='alert']");
    if (alertDismiss) {
      e.preventDefault();
      const alertEl = alertDismiss.closest(".alert");
      if (alertEl) alertEl.remove();
      return;
    }

    // 4. Toggle Dropdown: [data-bs-toggle="dropdown"]
    const dropdownTrigger = e.target.closest("[data-bs-toggle='dropdown']");
    if (dropdownTrigger) {
      e.preventDefault();
      e.stopPropagation();
      const parent = dropdownTrigger.closest(".dropdown") || dropdownTrigger.parentElement;
      const menu = parent ? parent.querySelector(".dropdown-menu") : null;
      const wasOpen = menu && menu.classList.contains("show");
      document.querySelectorAll(".dropdown-menu.show").forEach(function (m) {
        m.classList.remove("show");
      });
      if (menu && !wasOpen) {
        menu.classList.add("show");
      }
      return;
    }

    // Cerrar dropdowns abiertos al hacer clic fuera
    if (!e.target.closest(".dropdown-menu")) {
      document.querySelectorAll(".dropdown-menu.show").forEach(function (m) {
        m.classList.remove("show");
      });
    }

    // 5. Toggle Collapse: [data-bs-toggle="collapse"]
    const collapseTrigger = e.target.closest("[data-bs-toggle='collapse']");
    if (collapseTrigger) {
      e.preventDefault();
      const targetSel =
        collapseTrigger.getAttribute("data-bs-target") || collapseTrigger.getAttribute("href");
      if (targetSel) {
        const targetEl = document.querySelector(targetSel);
        if (targetEl) {
          targetEl.classList.toggle("d-none");
          targetEl.classList.toggle("show");
        }
      }
    }
  });

  // Cerrar modal activo con tecla Escape
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      document.querySelectorAll(".modal.show").forEach(function (m) {
        ArcaModal.getOrCreateInstance(m).hide();
      });
      document.querySelectorAll(".dropdown-menu.show").forEach(function (m) {
        m.classList.remove("show");
      });
    }
  });
})();

/**
 * Sincroniza visualmente todos los comboboxes arca-searchable-select con el valor actual de su <select>.
 */
window.arcaSyncSearchableSelects = function () {
  document.querySelectorAll("select.arca-searchable-select").forEach(function (select) {
    if (select.tomselect) {
      const defaultVal = select.options.length > 0 ? select.options[0].value : "";
      select.tomselect.setValue(select.value || defaultVal, true);
    } else if (typeof select._arcaSyncCombobox === "function") {
      select._arcaSyncCombobox();
    }
  });
};

/**
 * Formatea visualmente una opción en Tom Select con Badges de UO o Avatar de Usuario.
 */
function arcaFormatSelectEntry(select, data, escape, isItem) {
  const val = (data.value || "").toString();
  const rawText = (data.text || "").toString().trim();

  // Opción por defecto ("-- Todos... --")
  if (!val || (val === "all" && rawText.startsWith("--"))) {
    const cleanDefault = rawText.replace(/^--\s*/, "").replace(/\s*--$/, "");
    return '<span class="text-muted">' + escape(cleanDefault) + "</span>";
  }

  // Opción especial: Sin UO de origen (Asientos Personales)
  if (val === "NONE") {
    return (
      '<span class="d-inline-flex align-items-center gap-2">' +
      '<span class="arca-ts-badge arca-ts-badge-personal">PERSONAL</span>' +
      "<span>" +
      escape(rawText) +
      "</span>" +
      "</span>"
    );
  }

  // Formato UO "ALIAS - Nombre" (ej. TECH - Tecnología e Infraestructura)
  const uoDashMatch = rawText.match(/^([A-Z0-9_-]{2,16})\s+-\s+(.+)$/);
  if (uoDashMatch) {
    return (
      '<span class="d-inline-flex align-items-center gap-2 text-truncate">' +
      '<span class="arca-ts-badge">' +
      escape(uoDashMatch[1]) +
      "</span>" +
      '<span class="text-truncate">' +
      escape(uoDashMatch[2]) +
      "</span>" +
      "</span>"
    );
  }

  // Formato Usuario "username (Nombre Completo)" en selector de usuario
  if (select && select.id === "userFilterSelect") {
    const userMatch = rawText.match(/^([^\s(]+)(?:\s*\((.+)\))?$/);
    if (userMatch) {
      const uname = userMatch[1];
      const fullName = userMatch[2] || "";
      const initial = uname.charAt(0).toUpperCase();
      return (
        '<span class="d-inline-flex align-items-center gap-2 text-truncate">' +
        '<span class="arca-ts-avatar">' +
        escape(initial) +
        "</span>" +
        '<span class="fw-semibold">' +
        escape(uname) +
        "</span>" +
        (fullName && !isItem
          ? '<span class="text-muted small text-truncate">(' + escape(fullName) + ")</span>"
          : "") +
        "</span>"
      );
    }
  }

  return "<span>" + escape(rawText) + "</span>";
}

/**
 * Inicializa Tom Select (con tema Tailwind / Shadcn UI) sobre todos los <select class="... arca-searchable-select">
 * permitiendo tanto seleccionar de la lista desplegable como escribir para buscar/filtrar opciones.
 */
function arcaInitSearchableSelects() {
  document.querySelectorAll("select.arca-searchable-select").forEach(function (select) {
    if (select.dataset.boundSearchableSelect === "1") return;
    select.dataset.boundSearchableSelect = "1";

    const allowCustom = select.dataset.allowCustom === "1";
    const defaultOpt = select.options.length > 0 ? select.options[0] : null;
    const defaultVal = defaultOpt ? defaultOpt.value : "";
    const defaultLabel = defaultOpt
      ? defaultOpt.textContent.trim().replace(/^--\s*/, "").replace(/\s*--$/, "")
      : "";
    const placeholderText = select.getAttribute("data-placeholder") || defaultLabel;

    if (typeof TomSelect !== "undefined") {
      const ts = new TomSelect(select, {
        create: allowCustom
          ? function (input) {
              return { value: input.trim(), text: input.trim() };
            }
          : false,
        createOnBlur: allowCustom,
        persist: false,
        allowEmptyOption: true,
        maxOptions: 250,
        placeholder: placeholderText,
        plugins: ["clear_button"],
        render: {
          option: function (data, escape) {
            return (
              '<div class="option">' +
              arcaFormatSelectEntry(select, data, escape, false) +
              "</div>"
            );
          },
          item: function (data, escape) {
            return (
              '<div class="item">' +
              arcaFormatSelectEntry(select, data, escape, true) +
              "</div>"
            );
          },
          option_create: function (data, escape) {
            return (
              '<div class="create">Filtrar por: <strong>"' +
              escape(data.input) +
              '"</strong></div>'
            );
          },
          no_results: function (data, escape) {
            return (
              '<div class="no-results">Sin coincidencias para "' +
              escape(data.input) +
              '"</div>'
            );
          },
        },
        onChange: function (val) {
          if (val === "" && defaultVal !== "" && select.value !== defaultVal) {
            ts.setValue(defaultVal, true);
            select.value = defaultVal;
          }
          select.dispatchEvent(new Event("change", { bubbles: true }));
        },
      });
      return;
    }
  });
}

function arcaInitInteractiveComponents() {
  // 1. Inicializar Feather Icons si está disponible
  if (typeof feather !== "undefined") {
    feather.replace();
  }

  // 2. Inicializar Comboboxes seleccionables + búsqueda escrita (Tom Select Tailwind/Shadcn)
  arcaInitSearchableSelects();

  // 3. Formularios modales que disparan descargas forenses / certificadas
  // Cierra automáticamente el modal, descarga el archivo y refresca la vista
  document.querySelectorAll("form[data-download-modal-form]").forEach(function (form) {
    if (form.dataset.boundDownloadModal === "1") return;
    form.dataset.boundDownloadModal = "1";

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      const modalEl = form.closest(".modal");
      const formData = new FormData(form);
      const actionUrl = form.getAttribute("action") || window.location.href;

      // Cerrar inmediatamente el modal
      if (modalEl && window.bootstrap && window.bootstrap.Modal) {
        window.bootstrap.Modal.getOrCreateInstance(modalEl).hide();
      }

      fetch(actionUrl, {
        method: "POST",
        body: formData,
        credentials: "same-origin",
      })
        .then(function (response) {
          const disp = response.headers.get("Content-Disposition") || "";
          if (response.ok && disp.toLowerCase().includes("attachment")) {
            let filename = "arcamitte_certificado.bin";
            const match = disp.match(/filename="?([^";]+)"?/i);
            if (match && match[1]) {
              filename = match[1];
            }
            return response.blob().then(function (blob) {
              const blobUrl = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = blobUrl;
              a.download = filename;
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              setTimeout(function () {
                URL.revokeObjectURL(blobUrl);
              }, 2000);
              form.reset();
              setTimeout(function () {
                window.location.reload();
              }, 350);
            });
          } else {
            window.location.reload();
          }
        })
        .catch(function () {
          window.location.reload();
        });
    });
  });

  // 4. Enlaces de descarga reactiva (ej. Descarga de Auditoría Preservada)
  document.querySelectorAll("a[data-reactive-download]").forEach(function (link) {
    if (link.dataset.boundReactiveDownload === "1") return;
    link.dataset.boundReactiveDownload = "1";

    link.addEventListener("click", function () {
      setTimeout(function () {
        window.location.reload();
      }, 900);
    });
  });

  // 5. Filtro instantáneo reactivo en tablas locales (Usuarios / UOs)
  document.querySelectorAll("input[data-reactive-table-filter]").forEach(function (input) {
    if (input.dataset.boundTableFilter === "1") return;
    input.dataset.boundTableFilter = "1";

    const targetSelector = input.getAttribute("data-reactive-table-filter");
    input.addEventListener("input", function () {
      const term = (input.value || "").trim().toLowerCase();
      const tbody = document.querySelector(targetSelector);
      if (!tbody) return;
      tbody.querySelectorAll("tr").forEach(function (row) {
        if (row.querySelector("td[colspan]")) return;
        const text = (row.textContent || "").toLowerCase();
        row.style.display = !term || text.includes(term) ? "" : "none";
      });
    });
  });
}

document.addEventListener("DOMContentLoaded", function () {
  arcaInitInteractiveComponents();

  // Toggle del Sidebar
  const toggleBtn = document.getElementById("arcaSidebarToggle");
  const sidebar = document.getElementById("arcaSidebar");
  const overlay = document.getElementById("arcaSidebarOverlay");

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", function (e) {
      e.preventDefault();
      if (window.innerWidth < 992) {
        sidebar.classList.toggle("show");
        if (overlay) overlay.classList.toggle("show");
      } else {
        sidebar.classList.toggle("collapsed");
      }
    });
  }

  if (overlay) {
    overlay.addEventListener("click", function () {
      if (sidebar) sidebar.classList.remove("show");
      overlay.classList.remove("show");
    });
  }
});

// Re-inicializar iconos y manejadores tras cualquier intercambio HTMX
document.addEventListener("htmx:afterSwap", function () {
  arcaInitInteractiveComponents();
});

document.addEventListener("htmx:afterSettle", function () {
  arcaInitInteractiveComponents();
});

// Función de copiado al portapapeles para tokens y hashes
function arcaCopyToClipboard(inputId, feedbackId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.select();
  navigator.clipboard.writeText(input.value).then(() => {
    const feedback = document.getElementById(feedbackId);
    if (feedback) {
      feedback.style.display = "inline-block";
      setTimeout(() => {
        feedback.style.display = "none";
      }, 3000);
    }
  });
}
