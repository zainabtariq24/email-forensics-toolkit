// Progressive enhancement only: every form works without JavaScript.
(function () {
  document.documentElement.classList.add("js");

  document.addEventListener("DOMContentLoaded", function () {
    // Tabs: only the active panel's fields are submitted.
    var tabs = document.querySelectorAll(".tab");
    var panels = document.querySelectorAll(".tab-panel");
    function activate(name) {
      tabs.forEach(function (t) {
        var on = t.dataset.tab === name;
        t.classList.toggle("is-active", on);
        t.setAttribute("aria-selected", on ? "true" : "false");
      });
      panels.forEach(function (p) {
        var on = p.dataset.panel === name;
        p.classList.toggle("is-active", on);
        p.querySelectorAll("input, textarea, select").forEach(function (el) {
          el.disabled = !on;
        });
      });
    }
    tabs.forEach(function (t) {
      t.addEventListener("click", function () { activate(t.dataset.tab); });
    });
    if (tabs.length) activate("upload");

    // Drag-and-drop file selection.
    var zone = document.getElementById("dropzone");
    var input = document.getElementById("eml-file");
    function showFile(file) {
      if (!file) return;
      document.getElementById("dz-title").textContent = file.name;
      document.getElementById("dz-sub").textContent =
        (file.size / 1024).toFixed(1) + " KB · ready to analyse";
      zone.classList.add("has-file");
    }
    if (zone && input) {
      ["dragenter", "dragover"].forEach(function (ev) {
        zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add("is-drag"); });
      });
      ["dragleave", "drop"].forEach(function (ev) {
        zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove("is-drag"); });
      });
      zone.addEventListener("drop", function (e) {
        if (e.dataTransfer.files.length) {
          input.files = e.dataTransfer.files;
          showFile(input.files[0]);
        }
      });
      input.addEventListener("change", function () { showFile(input.files[0]); });
    }

    // Loading state on submit.
    var form = document.getElementById("analyze-form");
    if (form) {
      form.addEventListener("submit", function () {
        var btn = document.getElementById("submit-btn");
        btn.classList.add("is-loading");
        btn.querySelector(".btn-label").textContent = "Analysing…";
      });
    }

    // Copy-to-clipboard for the evidence hash.
    document.querySelectorAll(".copy-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var text = document.getElementById(btn.dataset.copy).textContent.trim();
        navigator.clipboard.writeText(text).then(function () {
          btn.textContent = "Copied";
          setTimeout(function () { btn.textContent = "Copy"; }, 1500);
        });
      });
    });
  });
})();
