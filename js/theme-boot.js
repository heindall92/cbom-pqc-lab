// Aplica el tema antes de pintar para evitar parpadeo.
(function () {
  try {
    var s = JSON.parse(localStorage.getItem("cbom-pqc-lab:v1") || "{}");
    var t = s.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.dataset.theme = t;
  } catch (e) {}
})();
