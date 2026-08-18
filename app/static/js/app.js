/* RailGate admin panel behaviour.
   All privileged calls go through the JSON API with the CSRF token that the
   server embedded in a <meta> tag for the current session. */

(function () {
  "use strict";

  var csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || "";
  var toastEl = document.getElementById("toast");
  var toastTimer = null;

  function toast(message, kind) {
    if (!toastEl) {
      window.alert(message);
      return;
    }
    toastEl.textContent = message;
    toastEl.className = "toast " + (kind === "error" ? "is-error" : "is-ok");
    toastEl.hidden = false;
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(function () {
      toastEl.hidden = true;
    }, kind === "error" ? 7000 : 3500);
  }

  function api(path, options) {
    var opts = options || {};
    var headers = { "X-CSRF-Token": csrfToken, "Accept": "application/json" };
    if (opts.body) {
      headers["Content-Type"] = "application/json";
    }
    return fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      credentials: "same-origin"
    }).then(function (response) {
      return response
        .json()
        .catch(function () {
          return {};
        })
        .then(function (data) {
          if (!response.ok) {
            var detail = data.detail || data.error || response.statusText;
            throw new Error(detail || "Request failed");
          }
          return data;
        });
    });
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.className = "sr-only";
      document.body.appendChild(area);
      area.select();
      try {
        var ok = document.execCommand("copy");
        document.body.removeChild(area);
        ok ? resolve() : reject(new Error("Copy was blocked by the browser."));
      } catch (err) {
        document.body.removeChild(area);
        reject(err);
      }
    });
  }

  function reloadSoon() {
    window.setTimeout(function () {
      window.location.reload();
    }, 700);
  }

  /* ------------------------------------------------------------ actions */
  var handlers = {
    "copy-text": function (button) {
      var target = document.getElementById(button.getAttribute("data-copy-target"));
      if (!target) {
        return;
      }
      copyText(target.textContent.trim()).then(
        function () {
          toast("Link copied to the clipboard.");
        },
        function (err) {
          toast(err.message, "error");
        }
      );
    },

    "copy-value": function (button) {
      copyText(button.getAttribute("data-value") || "").then(
        function () {
          toast("Copied.");
        },
        function (err) {
          toast(err.message, "error");
        }
      );
    },

    "copy-uri": function (button) {
      var id = button.getAttribute("data-user-id");
      api("/api/users/" + id + "/uri")
        .then(function (data) {
          return copyText(data.uri);
        })
        .then(function () {
          toast("VLESS link copied to the clipboard.");
        })
        .catch(function (err) {
          toast(err.message, "error");
        });
    },

    "toggle-qr": function (button) {
      var figure = document.getElementById(button.getAttribute("data-qr-target"));
      if (!figure) {
        return;
      }
      figure.hidden = !figure.hidden;
      button.textContent = figure.hidden ? "Show QR code" : "Hide QR code";
    },

    disable: function (button) {
      var id = button.getAttribute("data-user-id");
      api("/api/users/" + id + "/disable", { method: "POST" })
        .then(function () {
          toast("Account disabled.");
          reloadSoon();
        })
        .catch(function (err) {
          toast(err.message, "error");
        });
    },

    enable: function (button) {
      var id = button.getAttribute("data-user-id");
      api("/api/users/" + id + "/enable", { method: "POST" })
        .then(function () {
          toast("Account enabled.");
          reloadSoon();
        })
        .catch(function (err) {
          toast(err.message, "error");
        });
    },

    renew: function (button) {
      var id = button.getAttribute("data-user-id");
      var name = button.getAttribute("data-username") || "this account";
      var answer = window.prompt("Extend " + name + " by how many days? (0 = never expires)", "30");
      if (answer === null) {
        return;
      }
      var days = parseInt(answer, 10);
      if (isNaN(days) || days < 0) {
        toast("Enter a whole number of days.", "error");
        return;
      }
      api("/api/users/" + id + "/renew", { method: "POST", body: { days: days } })
        .then(function () {
          toast("Account renewed.");
          reloadSoon();
        })
        .catch(function (err) {
          toast(err.message, "error");
        });
    },

    regenerate: function (button) {
      var id = button.getAttribute("data-user-id");
      var name = button.getAttribute("data-username") || "this account";
      if (!window.confirm("Regenerate the UUID for " + name + "?\n\nEvery link and QR code already issued for this account will stop working.")) {
        return;
      }
      api("/api/users/" + id + "/regenerate", { method: "POST" })
        .then(function () {
          toast("New credentials generated.");
          reloadSoon();
        })
        .catch(function (err) {
          toast(err.message, "error");
        });
    },

    "delete": function (button) {
      var id = button.getAttribute("data-user-id");
      var name = button.getAttribute("data-username") || "this account";
      var redirect = button.getAttribute("data-redirect");
      if (!window.confirm("Delete " + name + " permanently?\n\nThe account is removed from the database and from the running Xray configuration. This cannot be undone.")) {
        return;
      }
      api("/api/users/" + id, { method: "DELETE" })
        .then(function () {
          toast("Account deleted.");
          if (redirect) {
            window.setTimeout(function () {
              window.location.href = redirect;
            }, 600);
          } else {
            reloadSoon();
          }
        })
        .catch(function (err) {
          toast(err.message, "error");
        });
    },

    "logout-all": function () {
      if (!window.confirm("Sign out of every session, including this one?")) {
        return;
      }
      api("/api/sessions", { method: "DELETE" })
        .then(function () {
          window.location.href = "/login";
        })
        .catch(function (err) {
          toast(err.message, "error");
        });
    }
  };

  /* -------------------------------------------------------------- tools */
  function runTool(button) {
    var action = button.getAttribute("data-tool");
    var output = document.getElementById("tool-output");
    var original = button.textContent;
    button.disabled = true;
    button.textContent = "Running…";

    api("/api/tools/" + action, { method: "POST" })
      .then(function (data) {
        if (output) {
          output.hidden = false;
          output.textContent = "== " + data.title + " ==\n\n" + data.output;
        }
        toast(data.ok ? data.title + ": done." : data.title + ": reported a problem.", data.ok ? "ok" : "error");
      })
      .catch(function (err) {
        if (output) {
          output.hidden = false;
          output.textContent = "Error: " + err.message;
        }
        toast(err.message, "error");
      })
      .finally(function () {
        button.disabled = false;
        button.textContent = original;
      });
  }

  function runResync(button) {
    var original = button.textContent;
    button.disabled = true;
    button.textContent = "Applying…";
    api("/api/resync", { method: "POST" })
      .then(function (data) {
        toast(data.message || "Configuration applied.", data.ok ? "ok" : "error");
      })
      .catch(function (err) {
        toast(err.message, "error");
      })
      .finally(function () {
        button.disabled = false;
        button.textContent = original;
      });
  }

  /* ---------------------------------------------------------- listeners */
  document.addEventListener("click", function (event) {
    var actionButton = event.target.closest("[data-action]");
    if (actionButton) {
      var handler = handlers[actionButton.getAttribute("data-action")];
      if (handler) {
        event.preventDefault();
        handler(actionButton);
      }
      return;
    }

    var toolButton = event.target.closest("[data-tool]");
    if (toolButton) {
      event.preventDefault();
      if (toolButton.getAttribute("data-tool") === "resync" && !document.getElementById("tool-output")) {
        runResync(toolButton);
      } else {
        runTool(toolButton);
      }
      return;
    }

    var themeButton = event.target.closest("[data-theme-toggle]");
    if (themeButton) {
      event.preventDefault();
      var root = document.documentElement;
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      try {
        window.localStorage.setItem("railgate-theme", next);
      } catch (e) {
        /* storage unavailable: the choice simply does not persist */
      }
    }
  });

  /* Reveal the custom-date field only when "Custom date" is selected. */
  var customDate = document.querySelector('input[name="custom_date"]');
  if (customDate) {
    var radios = document.querySelectorAll('input[name="expiry_choice"]');
    var syncCustom = function () {
      var selected = document.querySelector('input[name="expiry_choice"]:checked');
      var isCustom = selected && selected.value === "custom";
      customDate.hidden = !isCustom;
      customDate.required = !!isCustom;
    };
    Array.prototype.forEach.call(radios, function (radio) {
      radio.addEventListener("change", syncCustom);
    });
    syncCustom();
  }
})();
