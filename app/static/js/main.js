// ScamShield AI - Main Global Client Script

document.addEventListener("DOMContentLoaded", () => {
  // Auto-dismiss alert messages after 5 seconds
  const alerts = document.querySelectorAll(".alert");
  alerts.forEach(alert => {
    setTimeout(() => {
      alert.style.opacity = "0";
      alert.style.transition = "opacity 0.4s ease";
      setTimeout(() => alert.remove(), 400);
    }, 5000);
  });
});

function copyToClipboard(text, triggerBtn) {
  navigator.clipboard.writeText(text).then(() => {
    const originalText = triggerBtn.innerHTML;
    triggerBtn.innerHTML = "✓ Copied!";
    triggerBtn.classList.add("btn-success");
    setTimeout(() => {
      triggerBtn.innerHTML = originalText;
      triggerBtn.classList.remove("btn-success");
    }, 2000);
  }).catch(err => {
    console.error("Could not copy text: ", err);
  });
}
