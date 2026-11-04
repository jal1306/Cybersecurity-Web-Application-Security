document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("url");
  const clear = document.getElementById("clearUrl");
  const form = document.getElementById("scanForm");
  const button = document.getElementById("scanButton");
  if (clear && input) clear.addEventListener("click", () => { input.value = ""; input.focus(); });
  if (form && button) form.addEventListener("submit", () => {
    if (form.reportValidity()) {
      button.disabled = true;
      button.innerHTML = '<span class="spinner"></span> Scanning target…';
    }
  });
});
