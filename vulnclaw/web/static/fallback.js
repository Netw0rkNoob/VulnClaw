(function () {
  var root = document.documentElement;
  var buttons = document.querySelectorAll("[data-set-lang]");

  function setLang(lang) {
    root.lang = lang;
    buttons.forEach(function (button) {
      button.classList.toggle("active", button.getAttribute("data-set-lang") === lang);
    });
    try {
      localStorage.setItem("vulnclaw-fallback-lang", lang);
    } catch (_error) {
      // Storage can be unavailable in hardened browser contexts.
    }
  }

  buttons.forEach(function (button) {
    button.addEventListener("click", function () {
      setLang(button.getAttribute("data-set-lang") || "zh-CN");
    });
  });

  var saved = null;
  try {
    saved = localStorage.getItem("vulnclaw-fallback-lang");
  } catch (_error) {
    // Fall back to Chinese when storage is unavailable.
  }
  setLang(saved === "en" || saved === "zh-CN" ? saved : "zh-CN");
})();
