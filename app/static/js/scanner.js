// ScamShield AI - Multi-Input Scanner Controller

document.addEventListener("DOMContentLoaded", () => {
  // Tab Switching
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");

      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const activeContent = document.getElementById(`tab-${targetTab}`);
      if (activeContent) {
        activeContent.classList.add("active");
      }
    });
  });

  // Setup scanner form AJAX handlers
  setupFormHandler("form-message-scan", "/api/scan/text", "btn-scan-msg");
  setupFormHandler("form-email-scan", "/api/scan/email", "btn-scan-email");
  setupFormHandler("form-url-scan", "/api/scan/url", "btn-scan-url");
  setupFileFormHandler("form-image-scan", "/api/scan/image", "btn-scan-image", "image-file-input", "image-dropzone-text");
  setupFileFormHandler("form-pdf-scan", "/api/scan/pdf", "btn-scan-pdf", "pdf-file-input", "pdf-dropzone-text");
});

function setupFormHandler(formId, endpoint, btnId) {
  const form = document.getElementById(formId);
  const btn = document.getElementById(btnId);
  if (!form || !btn) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(form);
    const payload = {};
    formData.forEach((val, key) => payload[key] = val);

    setLoading(btn, true);
    clearScanAlert();

    try {
      const resp = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await resp.json();

      if (!resp.ok || !data.success) {
        showScanAlert(data.error || "Analysis failed. Please check your inputs.", "danger");
        setLoading(btn, false);
        return;
      }

      // Successful scan: redirect to detailed result view
      if (data.result_url) {
        window.location.href = data.result_url;
      } else if (data.scan_id) {
        window.location.href = `/scan/${data.scan_id}`;
      }
    } catch (err) {
      showScanAlert("Network error or connection lost: " + err.message, "danger");
      setLoading(btn, false);
    }
  });
}

function setupFileFormHandler(formId, endpoint, btnId, fileInputId, dropzoneTextId) {
  const form = document.getElementById(formId);
  const btn = document.getElementById(btnId);
  const fileInput = document.getElementById(fileInputId);
  const dropzoneText = document.getElementById(dropzoneTextId);
  if (!form || !btn || !fileInput) return;

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0 && dropzoneText) {
      dropzoneText.textContent = `Selected: ${fileInput.files[0].name} (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`;
    }
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!fileInput.files || fileInput.files.length === 0) {
      showScanAlert("Please select a file to upload.", "warning");
      return;
    }

    const formData = new FormData(form);
    setLoading(btn, true);
    clearScanAlert();

    try {
      const resp = await fetch(endpoint, {
        method: "POST",
        body: formData
      });
      const data = await resp.json();

      if (!resp.ok || !data.success) {
        showScanAlert(data.error || "File analysis failed.", "danger");
        setLoading(btn, false);
        return;
      }

      if (data.result_url) {
        window.location.href = data.result_url;
      } else if (data.scan_id) {
        window.location.href = `/scan/${data.scan_id}`;
      }
    } catch (err) {
      showScanAlert("Failed to process file: " + err.message, "danger");
      setLoading(btn, false);
    }
  });
}

function setLoading(btn, isLoading) {
  if (isLoading) {
    btn.dataset.originalHtml = btn.innerHTML;
    btn.innerHTML = `<span class="spinner" style="display:inline-block; width:16px; height:16px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:8px;"></span> Analyzing...`;
    btn.disabled = true;
  } else {
    btn.innerHTML = btn.dataset.originalHtml || "Analyze";
    btn.disabled = false;
  }
}

function showScanAlert(msg, type) {
  const container = document.getElementById("scanner-alert-area");
  if (!container) return;
  container.innerHTML = `
    <div class="alert alert-${type}">
      <span>${msg}</span>
      <button type="button" onclick="this.parentElement.remove()" style="background:none; border:none; color:inherit; font-weight:bold; cursor:pointer;">&times;</button>
    </div>
  `;
}

function clearScanAlert() {
  const container = document.getElementById("scanner-alert-area");
  if (container) container.innerHTML = "";
}

// Add simple CSS spin animation dynamically
const spinStyle = document.createElement("style");
spinStyle.innerHTML = "@keyframes spin { to { transform: rotate(360deg); } }";
document.head.appendChild(spinStyle);
