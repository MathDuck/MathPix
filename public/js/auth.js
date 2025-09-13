async function captchaLoad() {
    let captchaResponse = {};
    try { const r = await fetch("/api/captcha"); captchaResponse = await r.json(); } catch { captchaResponse = { prompt: 'Captcha', token: '' }; }
    const promptEl = document.getElementById("captchaPrompt");
    if (promptEl) promptEl.textContent = captchaResponse.prompt;
    return { token: captchaResponse.token };
}

document.addEventListener("DOMContentLoaded", async () => {
    const path = location.pathname;
    if (path === "/register") {
        let captchaData = await captchaLoad();
        const form = document.getElementById("registerForm");
        form.addEventListener("submit", async (ev) => {
            ev.preventDefault();
            const username = document.getElementById("username").value.trim();
            const email = document.getElementById("email").value.trim();
            const password = document.getElementById("password").value;
            const captcha = document.getElementById("captcha").value.trim();
            const msg = document.getElementById("msg");
            const registerResponse = await fetch("/api/register", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ email, password, captcha, captchaToken: captchaData.token, username })
            });
            const registerData = await registerResponse.json();
            if (registerResponse.ok) {
                location.replace("/");
            } else {
                msg.textContent = registerData.error || "Erreur";
                if (window.__toast) window.__toast(registerData.error || 'Erreur inscription', { type: 'error' });
                captchaData = await captchaLoad();
            }
        });
    } else if (path === "/login") {
        const form = document.getElementById("loginForm");
        form.addEventListener("submit", async (ev) => {
            ev.preventDefault();
            const identifier = document.getElementById("username").value.trim();
            const password = document.getElementById("password").value;
            const msg = document.getElementById("msg");
            const loginResponse = await fetch("/api/login", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ identifier, password })
            });
            const loginData = await loginResponse.json();
            if (loginResponse.ok) {
                location.replace("/");
            } else {
                msg.textContent = loginData.error || "Erreur";
                if (window.__toast) window.__toast(loginData.error || 'Erreur connexion', { type: 'error' });
            }
        });
        const resetBtn = document.getElementById("resetBtn");
        const resetSection = document.getElementById("resetSection");
        const resetSubmitBtn = document.getElementById("resetSubmitBtn");
        const resetEmailInput = document.getElementById("resetEmail");
        resetBtn.addEventListener("click", () => {
            const expanded = resetBtn.getAttribute("aria-expanded") === "true";
            resetBtn.setAttribute("aria-expanded", String(!expanded));
            resetSection.style.display = expanded ? "none" : "block";
            if (!expanded) {
                resetEmailInput.setAttribute("required", "true");
                resetEmailInput.focus();
            } else {
                resetEmailInput.removeAttribute("required");
                resetEmailInput.value = "";
            }
        });
        resetSubmitBtn.addEventListener("click", async () => {
            const email = resetEmailInput.value.trim();
            const msg = document.getElementById("resetMsg");
            if (!email) { msg.textContent = "Entrez un email"; return; }
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { msg.textContent = "Email invalide"; return; }
            msg.textContent = "Envoi...";
            await fetch("/api/password/reset/request", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ email })
            });
            msg.textContent = "Si l’email existe, un lien a été envoyé.";
            if (window.__toast) window.__toast('Requête de réinitialisation envoyée', { type: 'success' });
        });
    }
});