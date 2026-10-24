/**
 * ARCAMITTE - Script de Soporte e Interactividad para el Panel
 */
document.addEventListener("DOMContentLoaded", function () {
  // Inicializar Feather Icons si está disponible
  if (typeof feather !== "undefined") {
    feather.replace();
  }

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
