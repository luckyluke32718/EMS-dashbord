async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
  if (!(response.headers.get("content-type") || "").includes("application/json")) {
    throw new Error("The API returned a web page instead of JSON. Run `npm start` in the project folder and open http://127.0.0.1:3000 (not Live Server).");
  }
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error("The API response was not valid JSON. Restart the app with `npm start`.");
  }
  if (!response.ok) throw new Error(result.error || "The request could not be completed.");
  return result;
}

function showFormError(status, error) {
  status.textContent = error.message;
  status.setAttribute("role", "alert");
}

const loginForm = document.getElementById("login-form");
if (loginForm) {
  const status = document.getElementById("login-status");
  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    status.textContent = "";
    const formData = new FormData(loginForm);
    try {
      await requestJson("/api/login", {
        method: "POST",
        body: JSON.stringify({ email: formData.get("email"), password: formData.get("password") }),
      });
      window.location.assign("/");
    } catch (error) {
      showFormError(status, error);
    }
  });
}

const registerForm = document.getElementById("register-form");
if (registerForm) {
  const status = document.getElementById("register-status");
  registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    status.textContent = "";
    const formData = new FormData(registerForm);
    try {
      await requestJson("/api/register", {
        method: "POST",
        body: JSON.stringify({ email: formData.get("email"), password: formData.get("password") }),
      });
      window.location.assign("/");
    } catch (error) {
      showFormError(status, error);
    }
  });
}

const reportForm = document.getElementById("ems-form");
if (reportForm) {
  const status = document.getElementById("form-status");
  let newReportStarted = new URLSearchParams(window.location.search).get("new") === "1";

  if (newReportStarted) {
    status.textContent = "New report started. Your saved report has not changed until you save.";
  } else {
    requestJson("/api/report")
      .then((report) => {
        if (newReportStarted) return;
        for (const [name, value] of Object.entries(report)) {
          if (name === "updatedAt") continue;
          if (name === "conditions" && Array.isArray(value)) {
            for (const checkbox of reportForm.querySelectorAll('input[name="conditions"]')) {
              checkbox.checked = value.includes(checkbox.value);
            }
            continue;
          }
          const field = reportForm.elements.namedItem(name);
          if (field && "value" in field && typeof value === "string") field.value = value;
        }
      })
      .catch((error) => {
        if (error.message.includes("log in")) window.location.assign("/login");
        else showFormError(status, error);
      });
  }

  const newReportLink = document.getElementById("new-report-link");
  if (newReportLink) newReportLink.addEventListener("click", () => reportForm.reset());

  reportForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    status.textContent = "Saving your report…";
    const report = Object.fromEntries(new FormData(reportForm).entries());
    report.conditions = Array.from(reportForm.querySelectorAll('input[name="conditions"]:checked'), (input) => input.value);
    try {
      const result = await requestJson("/api/report", { method: "POST", body: JSON.stringify(report) });
      if (!result.discordDelivered) {
        throw new Error(result.warning || "Your report was saved, but it could not be sent to Discord.");
      }
      window.location.assign("/");
    } catch (error) {
      showFormError(status, error);
    }
  });

  reportForm.addEventListener("reset", () => {
    newReportStarted = true;
    status.textContent = "New report started. Your saved report has not changed until you save.";
    status.removeAttribute("role");
  });

}

const logoutButton = document.getElementById("logout-button");
if (logoutButton) {
  logoutButton.addEventListener("click", async () => {
    try {
      await requestJson("/api/logout", { method: "POST", body: "{}" });
      window.location.assign(window.location.pathname === "/" ? "/" : "/login");
    } catch (error) {
      const status = document.getElementById("form-status") || document.getElementById("owner-status");
      if (status) showFormError(status, error);
    }
  });
}

const homeAuthButton = document.getElementById("home-auth-button");
if (homeAuthButton) {
  let isSignedIn = false;
  homeAuthButton.addEventListener("click", async () => {
    if (!isSignedIn) {
      window.location.assign("/login");
      return;
    }
    try {
      await requestJson("/api/logout", { method: "POST", body: "{}" });
      window.location.assign("/");
    } catch (error) {
      console.error("Unable to log out:", error);
    }
  });

  requestJson("/api/me")
    .then((identity) => {
      isSignedIn = Boolean(identity.role);
      if (isSignedIn) {
        homeAuthButton.textContent = "Log out";
        document.querySelectorAll(".login-prompt").forEach((link) => { link.hidden = true; });
      }
    })
    .catch((error) => console.error("Unable to check the current sign-in:", error));
}

const ownerLoginForm = document.getElementById("owner-login-form");
const ownerPanel = document.getElementById("owner-panel");
if (ownerLoginForm && ownerPanel) {
  const loginSection = document.getElementById("owner-login-section");
  const loginStatus = document.getElementById("owner-login-status");

  async function loadOwnerDashboard() {
    const identity = await requestJson("/api/me");
    if (identity.role !== "owner") return;
    logoutButton.hidden = false;
    const dashboard = await requestJson("/api/owner/dashboard");
    loginSection.hidden = true;
    ownerPanel.hidden = false;
    document.getElementById("owner-email").textContent = identity.email;
    renderOwnerDashboard(dashboard);
  }

  function renderOwnerDashboard(dashboard) {
    const usersBody = document.getElementById("users-list");
    const reportsList = document.getElementById("reports-list");
    usersBody.replaceChildren();
    reportsList.replaceChildren();

    for (const user of dashboard.users) {
      const row = document.createElement("tr");
      const email = document.createElement("td");
      email.textContent = user.displayName ? `${user.displayName} (${user.email})` : user.email;
      const created = document.createElement("td");
      created.textContent = new Date(user.createdAt).toLocaleDateString();
      const state = document.createElement("td");
      state.textContent = user.disabled ? "Disabled" : "Active";
      const actions = document.createElement("td");
      const toggle = document.createElement("button");
      toggle.type = "button";
      toggle.textContent = user.disabled ? "Enable" : "Disable";
      toggle.addEventListener("click", async () => {
        try {
          await requestJson(`/api/owner/users/${encodeURIComponent(user.id)}`, {
            method: "PATCH",
            body: JSON.stringify({ disabled: !user.disabled }),
          });
          await loadOwnerDashboard();
        } catch (error) {
          setOwnerStatus(error.message);
        }
      });
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Delete";
      remove.addEventListener("click", async () => {
        if (!window.confirm(`Delete ${user.email} and their saved EMS report? This cannot be undone.`)) return;
        try {
          await requestJson(`/api/owner/users/${encodeURIComponent(user.id)}`, { method: "DELETE" });
          await loadOwnerDashboard();
        } catch (error) {
          setOwnerStatus(error.message);
        }
      });
      actions.append(toggle, document.createTextNode(" "), remove);
      row.append(email, created, state, actions);
      usersBody.append(row);
    }

    if (dashboard.users.length === 0) {
      const row = document.createElement("tr");
      const empty = document.createElement("td");
      empty.colSpan = 4;
      empty.textContent = "No accounts yet.";
      row.append(empty);
      usersBody.append(row);
    }

    for (const item of dashboard.reports) {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = `${item.email} · updated ${new Date(item.report.updatedAt).toLocaleString()}`;
      const pre = document.createElement("pre");
      const fields = Object.fromEntries(
        Object.entries(item.report).filter(([key]) =>
          !["updatedAt", "reviewStatus", "discordReviewMessageId", "reviewedAt", "reviewedBy"].includes(key),
        ),
      );
      pre.textContent = JSON.stringify(fields, null, 2);
      details.append(summary, pre);
      reportsList.append(details);
    }

    if (dashboard.reports.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "No saved reports yet.";
      reportsList.append(empty);
    }
  }

  function setOwnerStatus(message) {
    document.getElementById("owner-status").textContent = message;
  }

  ownerLoginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    loginStatus.textContent = "";
    const formData = new FormData(ownerLoginForm);
    try {
      await requestJson("/api/owner/login", {
        method: "POST",
        body: JSON.stringify({ email: formData.get("email"), password: formData.get("password") }),
      });
      await loadOwnerDashboard();
    } catch (error) {
      showFormError(loginStatus, error);
    }
  });

  const addUserForm = document.getElementById("owner-add-user-form");
  const addUserStatus = document.getElementById("owner-add-user-status");
  addUserForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    addUserStatus.textContent = "";
    const formData = new FormData(addUserForm);
    try {
      const user = await requestJson("/api/owner/users", {
        method: "POST",
        body: JSON.stringify({
          name: formData.get("name"),
          email: formData.get("email"),
          password: formData.get("password"),
        }),
      });
      addUserForm.reset();
      addUserStatus.textContent = `${user.displayName} was added. Share the initial password with them privately.`;
      await loadOwnerDashboard();
    } catch (error) {
      showFormError(addUserStatus, error);
    }
  });

  loadOwnerDashboard().catch((error) => showFormError(loginStatus, error));
}
