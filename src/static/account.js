document.addEventListener("DOMContentLoaded", () => {
  const notice = document.getElementById("notice");
  const providers = document.getElementById("providers");
  const masterCard = document.getElementById("master-cv-card");
  const cvEditor = document.getElementById("cv-json");
  let csrfToken = "";
  let cvVersion = 0;

  function showMessage(message, isError = false) {
    notice.textContent = message;
    notice.classList.toggle("error", isError);
    notice.hidden = false;
  }

  async function request(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    });
    const data = response.status === 204 ? null : await response.json();
    if (!response.ok) throw new Error(data?.detail || data?.message || "The request could not be completed.");
    return data;
  }

  function formData(form) {
    return Object.fromEntries(new FormData(form).entries());
  }

  async function loadMasterCV() {
    const csrf = await request("/auth/csrf");
    csrfToken = csrf.csrf_token;
    const cv = await request("/master-cv/me");
    cvVersion = cv.version;
    cvEditor.value = JSON.stringify(cv.content, null, 2);
    document.getElementById("cv-version").textContent = `Revision ${cv.version}`;
    masterCard.hidden = false;
  }

  async function loadProviders() {
    try {
      const { providers: configured } = await request("/auth/providers");
      providers.replaceChildren();
      const labels = { google: "Google", microsoft: "Microsoft", oidc: "Single sign-on" };
      configured.forEach((provider) => {
        const link = document.createElement("a");
        link.className = "provider-button";
        link.href = `/auth/oauth/${encodeURIComponent(provider)}`;
        link.textContent = `Continue with ${labels[provider] || "your identity provider"}`;
        link.setAttribute("role", "button");
        providers.appendChild(link);
      });
      if (!configured.length) {
        providers.textContent = "Social sign-in is available when an identity provider is configured.";
      }
    } catch (error) {
      providers.textContent = "Identity providers are temporarily unavailable.";
    }
  }

  async function checkSession() {
    try {
      await request("/auth/me");
      await loadMasterCV();
    } catch (error) {
      masterCard.hidden = true;
    }
  }

  document.getElementById("register-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await request("/auth/register", {
        method: "POST",
        body: JSON.stringify(formData(event.currentTarget)),
      });
      showMessage(`A verification link was sent to ${result.email}. Verify your email before signing in.`);
    } catch (error) {
      showMessage(error.message, true);
    }
  });

  document.getElementById("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await request("/auth/login", { method: "POST", body: JSON.stringify(formData(event.currentTarget)) });
      await loadMasterCV();
      showMessage("You are signed in.");
    } catch (error) {
      showMessage(error.message, true);
    }
  });

  document.getElementById("verification-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await request("/auth/verify-email", { method: "POST", body: JSON.stringify(formData(event.currentTarget)) });
      await loadMasterCV();
      showMessage("Your email is verified and you are signed in.");
    } catch (error) {
      showMessage(error.message, true);
    }
  });

  document.getElementById("resend-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await request("/auth/request-verification", {
        method: "POST",
        body: JSON.stringify(formData(event.currentTarget)),
      });
      showMessage(result.message);
    } catch (error) {
      showMessage(error.message, true);
    }
  });

  document.getElementById("forgot-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const result = await request("/auth/forgot-password", {
        method: "POST",
        body: JSON.stringify(formData(event.currentTarget)),
      });
      showMessage(result.message);
    } catch (error) {
      showMessage(error.message, true);
    }
  });

  document.getElementById("reset-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await request("/auth/reset-password", {
        method: "POST",
        body: JSON.stringify(formData(event.currentTarget)),
      });
      event.currentTarget.reset();
      showMessage("Your password has been updated. Sign in with your new password.");
    } catch (error) {
      showMessage(error.message, true);
    }
  });

  document.getElementById("save-cv").addEventListener("click", async () => {
    try {
      const content = JSON.parse(cvEditor.value);
      const saved = await request("/master-cv/me", {
        method: "PUT",
        headers: { "X-CSRF-Token": csrfToken },
        body: JSON.stringify({ expected_version: cvVersion, content }),
      });
      cvVersion = saved.version;
      document.getElementById("cv-version").textContent = `Revision ${saved.version}`;
      showMessage("Master CV saved.");
    } catch (error) {
      showMessage(error instanceof SyntaxError ? "CV data must be valid JSON." : error.message, true);
    }
  });

  document.getElementById("delete-cv").addEventListener("click", async () => {
    if (!window.confirm("Delete your Master CV and its saved revisions? This cannot be undone.")) return;
    try {
      await request("/master-cv/me", { method: "DELETE", headers: { "X-CSRF-Token": csrfToken } });
      cvVersion = 0;
      cvEditor.value = "{}";
      document.getElementById("cv-version").textContent = "No saved Master CV";
      showMessage("Master CV and revisions deleted.");
    } catch (error) {
      showMessage(error.message, true);
    }
  });

  document.getElementById("logout-button").addEventListener("click", async () => {
    try {
      await request("/auth/logout", { method: "POST", headers: { "X-CSRF-Token": csrfToken } });
      masterCard.hidden = true;
      showMessage("You have signed out.");
    } catch (error) {
      showMessage(error.message, true);
    }
  });

  const query = new URLSearchParams(window.location.search);
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  if (fragment.has("verify")) document.querySelector('#verification-form [name="token"]').value = fragment.get("verify");
  if (fragment.has("reset")) document.querySelector('#reset-form [name="token"]').value = fragment.get("reset");
  if (fragment.has("verify") || fragment.has("reset")) {
    window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
  }
  if (query.has("oauth")) showMessage("Identity sign-in complete.");
  loadProviders();
  checkSession();
});
