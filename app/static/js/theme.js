/* Applied before first paint so switching themes does not flash.
   Loaded synchronously from <head>; CSP forbids inline scripts. */
(function () {
  try {
    var stored = window.localStorage.getItem("railgate-theme");
    var prefersLight =
      window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
    var theme = stored || (prefersLight ? "light" : "dark");
    document.documentElement.setAttribute("data-theme", theme);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "dark");
  }
})();
