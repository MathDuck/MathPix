document.addEventListener("DOMContentLoaded", async () => {
    const BASE_URL = window.__BASE_URL || ((location.hostname === '127.0.0.1' || location.hostname === 'localhost')
        ? 'http://127.0.0.1:8787'
        : 'https://cdn.mduck.fr');
    const sections = document.querySelectorAll(".settings-section");
    const navLinks = document.querySelectorAll(".nav-link");

    // Helpers
    const $ = (id) => document.getElementById(id);
    const on = (id, evt, handler) => { const el = $(id); if (el) el.addEventListener(evt, handler); return el; };
    const toast = (msg, opts) => { if (window.__toast) window.__toast(msg, opts); };
    const safeJSON = async (res) => { try { return await res.clone().json(); } catch { return {}; } };

    // Navigation entre sections
    navLinks.forEach(link => {
        link.addEventListener("click", e => {
            e.preventDefault();
            const target = link.dataset.section;

            navLinks.forEach(l => l.classList.remove("active"));
            link.classList.add("active");

            sections.forEach(sec => {
                sec.classList.toggle("active", sec.id === target);
            });
        });
    });

    // Récupération infos utilisateur
    try { // Récupération infos utilisateur
        const res = await fetch("/api/me");
        const me = await res.json(); // /api/me doit toujours renvoyer JSON
        if (me.error || !me.info) {
            window.location.href = "/login";
            return;
        }
        const info = me.info;
        const stats = me.stats;
        const setText = (id, value) => { const el = $(id); if (el) el.textContent = value; };
        setText("usernameDisplay", info.username || info.email);
        // menuUsername et menuRole laissés à header.js pour éviter double écriture
        const currentImg = $("currentProfileImg");
        const largeCircle = document.querySelector(".avatar-circle.large");
        if (info.avatar_url && currentImg) {
            currentImg.src = info.avatar_url; // déjà relative /a/
        } else if (largeCircle) {
            if (currentImg) currentImg.remove();
            const initial = (info.username || info.email || "?").trim().charAt(0).toUpperCase();
            largeCircle.textContent = initial;
        }
        const accountInfoEl = $("accountInfo");
        if (accountInfoEl) accountInfoEl.innerHTML = `
            <div><strong>Email :</strong> ${info.email}</div>
            <div><strong>Username :</strong> ${info.username || '-'}</div>
            <div><strong>Rôle :</strong> <span class="role-badge role-${info.role}">${info.role_label || info.role}</span></div>
            <div><strong>Créé le :</strong> ${new Date(info.created_at * 1000).toLocaleString()}</div>
        `;
        // === Statistiques === (4 stat-box + timeline + actions)
        const statsSection = $("stats-section");
        if (statsSection && stats) {
            const statsGrid = $('statsGrid');
            const formatBytes = (b) => (window.formatBytesProxy ? window.formatBytesProxy(b) : (window.formatBytes ? window.formatBytes(b) : (b + ' B')));
            if (statsGrid) {
                const parts = [];
                parts.push(`<div class="stat-box"><div class="stat-label">📤 Images uploadées</div><div class="stat-value">${stats.total ?? 0}</div></div>`);
                parts.push(`<div class="stat-box"><div class="stat-label">📦 Espace images</div><div class="stat-value">${formatBytes(stats.images_bytes_total || stats.bytes_total || 0)}</div></div>`);
                parts.push(`<div class="stat-box"><div class="stat-label">👤 Avatar</div><div class="stat-value">${formatBytes(stats.avatar_bytes || 0)}</div></div>`);
                parts.push(`<div class="stat-box"><div class="stat-label">Σ Total</div><div class="stat-value">${formatBytes(stats.bytes_total || ((stats.images_bytes_total || 0) + (stats.avatar_bytes || 0)))}</div></div>`);
                parts.push(`<div class="stat-box"><div class="stat-label">🔗 Appels API</div><div class="stat-value">${stats.audit?.api_token_refreshes ?? 0}</div></div>`);
                parts.push(`<div class="stat-box"><div class="stat-label">🖼 Changements de photo</div><div class="stat-value">${stats.audit?.avatar_changes ?? 0}</div></div>`);
                parts.push(`<div class="stat-box"><div class="stat-label">🔐 Changements de mot de passe</div><div class="stat-value">${stats.audit?.password_changes ?? 0}</div></div>`);
                statsGrid.innerHTML = parts.join('');
            }
            // Timeline
            let timeline = statsSection.querySelector('.stats-timeline');
            if (!timeline) { timeline = document.createElement('div'); timeline.className = 'stats-timeline'; statsSection.appendChild(timeline); }
            const fmtDate = ts => ts ? new Date(ts * 1000).toLocaleString(undefined, {
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit'
            }) : '-';
            timeline.innerHTML = `
                <h4>📅 Timeline</h4>
                <div class="timeline-grid">
                    <div class="timeline-item"><label>Premier upload</label><span class="timeline-value">${fmtDate(stats.first_upload_at)}</span></div>
                    <div class="timeline-item"><label>Dernier upload</label><span class="timeline-value">${fmtDate(stats.last_upload_at)}</span></div>
                    <div class="timeline-item"><label>Dernière activité</label><span class="timeline-value">${fmtDate(stats.last_upload_at)}</span></div>
                </div>`;
            // Ancienne section actions supprimée : stats fusionnées dans statsGrid
        }
        const currentEmailInput = $("currentEmail");
        if (currentEmailInput) currentEmailInput.value = info.email;
        if (info.role === "admin") {
            const adminLink = $("adminMenuLink");
            if (adminLink) adminLink.style.display = "";
        }
        // Pas de token automatique : l'utilisateur doit cliquer pour générer.
    } catch (err) {
        console.error("Erreur chargement session", err);
    }

    // === Upload avatar (drag & drop + paste image ou lien) ===
    const profileUploadZone = $("profileUploadZone");
    if (profileUploadZone && !profileUploadZone.hasAttribute('tabindex')) profileUploadZone.setAttribute('tabindex', '0');

    let avatarCooldownUntil = 0;

    function handleAvatarCooldown(waitSeconds) {
        const now = Date.now();
        avatarCooldownUntil = Math.max(avatarCooldownUntil, now + waitSeconds * 1000);
        const remaining = Math.ceil((avatarCooldownUntil - now) / 1000);
        if (window.__toastCountdown) {
            window.__toastCountdown(remaining, { message: 'Merci de patienter pendant {s}s' });
        } else if (window.__toast) {
            window.__toast('Cooldown avatar ' + remaining + 's', { type: 'error', ttl: 4000 });
        }
    }

    function avatarInCooldown() {
        const now = Date.now();
        if (avatarCooldownUntil && now < avatarCooldownUntil) {
            handleAvatarCooldown(Math.ceil((avatarCooldownUntil - now) / 1000));
            return true;
        }
        return false;
    }

    async function uploadProfileFile(file) {
        const now = Date.now();
        if (avatarInCooldown()) return;
        const fd = new FormData();
        fd.append("file", file);
        const res = await fetch("/api/me/avatar", { method: "POST", body: fd });
        const data = await safeJSON(res);
        if (res.ok) {
            toast('Avatar mis à jour', { type: 'success' });
            location.reload();
        } else {
            if ((data).error === 'Cooldown avatar' && typeof (data).wait === 'number') {
                handleAvatarCooldown((data).wait);
            } else {
                toast((data).error || "Erreur avatar", { type: 'error' });
            }
        }
    }

    async function uploadProfileFromUrl(url) {
        if (avatarInCooldown()) return;
        try {
            const r = await fetch(url);
            if (!r.ok) { toast('Téléchargement impossible', { type: 'error' }); return alert("Téléchargement impossible"); }
            const ct = r.headers.get("content-type") || "image/jpeg";
            if (!/^image\/(png|jpe?g|webp|avif)$/.test(ct)) { toast('Format non supporté', { type: 'error' }); return alert("Format non supporté"); }
            const blob = await r.blob();
            const ext = ct.includes("png") ? ".png" : ct.includes("webp") ? ".webp" : ct.includes("avif") ? ".avif" : ".jpg";
            const file = new File([blob], "remote" + ext, { type: ct });
            await uploadProfileFile(file);
        } catch (e) { toast("Erreur import URL", { type: 'error' }); alert("Erreur lors de l'import depuis l'URL"); }
    }

    if (profileUploadZone) {
        // Drag & drop
        profileUploadZone.addEventListener("dragover", e => {
            e.preventDefault();
            profileUploadZone.classList.add("dragover");
        });
        profileUploadZone.addEventListener("dragleave", () => {
            profileUploadZone.classList.remove("dragover");
        });
        profileUploadZone.addEventListener("drop", e => {
            e.preventDefault();
            profileUploadZone.classList.remove("dragover");
            if (e.dataTransfer.files.length) {
                uploadProfileFile(e.dataTransfer.files[0]);
            }
        });
    }

    // Sélection via bouton / input fichier
    const chooseBtn = $("chooseProfileBtn");
    const fileInput = $("profileFileInput");
    if (chooseBtn && fileInput) {
        chooseBtn.addEventListener("click", (e) => {
            e.preventDefault();
            fileInput.click();
        });
        fileInput.addEventListener("change", () => {
            if (fileInput.files && fileInput.files[0]) {
                uploadProfileFile(fileInput.files[0]);
            }
        });
    }
    // Cliquer dans la zone (hors boutons existants) ouvre aussi le sélecteur
    if (profileUploadZone) {
        profileUploadZone.addEventListener("click", (e) => {
            if (!fileInput) return;
            if ((e.target instanceof HTMLElement) && e.target.closest('#chooseProfileBtn')) return; // évite double ouverture
            fileInput.click();
        });
    }

    // Coller image ou lien
    if (profileUploadZone) {
        profileUploadZone.addEventListener("paste", e => {
            const item = Array.from(e.clipboardData.items).find(i => i.type.startsWith("image/"));
            if (item) { uploadProfileFile(item.getAsFile()); return; }
            const text = e.clipboardData.getData("text");
            if (text && /\.(png|jpe?g|webp|avif)$/i.test(text)) uploadProfileFromUrl(text.trim());
        });
        // Fallback global: si l'utilisateur colle ailleurs mais la section avatar est active
        document.addEventListener('paste', e => {
            if (!document.getElementById('profile-section')?.classList.contains('active')) return;
            // Éviter double traitement si zone a déjà capturé
            if (document.activeElement === profileUploadZone) return;
            const item = Array.from(e.clipboardData?.items || []).find(i => i.type.startsWith('image/'));
            if (item) { uploadProfileFile(item.getAsFile()); return; }
            const text = e.clipboardData?.getData('text');
            if (text && /\.(png|jpe?g|webp|avif)$/i.test(text)) uploadProfileFromUrl(text.trim());
        });
    }

    // Supprimer avatar
    on("removeProfileBtn", "click", async () => {
        if (!confirm("Supprimer votre photo de profil ?")) return;
        const res = await fetch("/api/me/avatar", { method: "DELETE" });
        const data = await safeJSON(res);
        if (res.ok) {
            toast('Avatar supprimé', { type: 'info' });
            location.reload();
        } else {
            if ((data).error === 'Cooldown avatar' && typeof (data).wait === 'number') {
                if (window.__toastCountdown) window.__toastCountdown((data).wait, { message: 'Merci de patienter pendant {s}s' });
                else toast('Cooldown avatar ' + (data).wait + 's', { type: 'error', ttl: 4000 });
            } else {
                toast((data).error || 'Erreur suppression avatar', { type: 'error' });
            }
        }
    });

    // === Changer email ===
    on("changeEmailForm", "submit", async e => {
        e.preventDefault();
        const body = {
            new_email: $("newEmail").value,
            password: $("passwordForEmail").value
        };
        const res = await fetch("/api/me/email/request", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
        const data = await safeJSON(res);
        if (res.ok) { toast('Email changé', { type: 'success' }); location.reload(); }
        else { toast(data.error || 'Erreur changement email', { type: 'error' }); alert(data.error || "Erreur lors du changement d'email"); }
    });

    // === Changer mot de passe ===
    on("changePasswordForm", "submit", async e => {
        e.preventDefault();
        const body = {
            current: $("currentPassword").value,
            next: $("newPassword").value
        };
        if ($("confirmNewPassword").value !== body.next) {
            alert("Confirmation différente");
            return;
        }
        const res = await fetch("/api/me/password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
        const data = await safeJSON(res);
        if (res.ok) { toast('Mot de passe changé', { type: 'success' }); e.target.reset(); }
        else { toast(data.error || 'Erreur changement mot de passe', { type: 'error' }); alert(data.error || "Erreur lors du changement de mot de passe"); }
    });

    // === Token API ===
    const refreshBtn = $("refreshTokenBtn");
    const revokeBtn = $("revokeTokenBtn");
    const sharexBtn = $("downloadShareXBtn");
    const tokenInput = $("apiToken");
    const copyBtn = $("copyTokenBtn");
    const LOCAL_TOKEN_KEY = "apiTokenValue";
    const tokenMetaBox = $("tokenMeta");

    async function loadTokenMeta() {
        if (!tokenMetaBox) return;
        try {
            const r = await fetch('/api/me/token/meta');
            const j = await safeJSON(r);
            if (j.ok && j.meta) {
                const { created_at, last_used_at } = j.meta;
                const fmt = ts => ts ? new Date(ts * 1000).toLocaleString() : '-';
                tokenMetaBox.style.display = '';
                tokenMetaBox.innerHTML = `📅 Créé: <strong>${fmt(created_at)}</strong> • Dernier usage: <strong>${fmt(last_used_at)}</strong>`;
                if (revokeBtn) revokeBtn.style.display = '';
            } else {
                tokenMetaBox.style.display = 'none';
                if (revokeBtn) revokeBtn.style.display = 'none';
            }
        } catch { }
    }

    // Restaure token depuis localStorage si présent (ne peut pas être récupéré du serveur)
    // Récupère token serveur si disponible (sinon fallback localStorage)
    if (tokenInput) {
        try {
            const r = await fetch('/api/me/token/current');
            const j = await safeJSON(r);
            if (j.ok && j.token) {
                tokenInput.value = j.token;
                try { localStorage.setItem(LOCAL_TOKEN_KEY, j.token); } catch { }
            } else {
                const stored = localStorage.getItem(LOCAL_TOKEN_KEY);
                if (stored) tokenInput.value = stored;
            }
        } catch {
            const stored = localStorage.getItem(LOCAL_TOKEN_KEY);
            if (stored) tokenInput.value = stored;
        }
        if (!tokenInput.value) {
            tokenInput.placeholder = "Générez un token";
        }
    }
    // Si aucune valeur locale et meta indiquera existence côté serveur, loadTokenMeta() ajoutera un message; sinon placeholder déjà mis.

    // Ajout bouton visibilité (masqué par défaut)
    let visBtnRef = null;
    function updateTokenControls() {
        const hasToken = !!(tokenInput && tokenInput.value.trim());
        if (visBtnRef) visBtnRef.disabled = !hasToken;
        if (copyBtn) copyBtn.disabled = !hasToken;
    }

    if (tokenInput && !tokenInput.dataset.visibilityEnhanced) {
        try { tokenInput.type = "password"; } catch (_) { }
        const visBtn = document.createElement("button");
        visBtn.type = "button";
        visBtn.textContent = "👁️"; // œil = afficher
        visBtn.className = "token-visibility-btn";
        tokenInput.parentElement.insertBefore(visBtn, (tokenInput.nextSibling));
        visBtnRef = visBtn;
        // Déplacer le bouton copier juste après l'œil pour même style
        if (copyBtn) {
            copyBtn.className = "token-visibility-btn";
            copyBtn.textContent = "📋";
            tokenInput.parentElement.insertBefore(copyBtn, visBtn.nextSibling);
        }
        let visible = false;
        visBtn.addEventListener("click", () => {
            if (visBtn.disabled) return;
            visible = !visible;
            if (visible) {
                try { tokenInput.type = "text"; } catch (_) { }
                visBtn.textContent = "🙈";
            } else {
                try { tokenInput.type = "password"; } catch (_) { }
                visBtn.textContent = "👁️";
            }
        });
        tokenInput.dataset.visibilityEnhanced = "1";
        updateTokenControls();
    }

    function updateShareXVisibility() {
        if (!sharexBtn) return;
        sharexBtn.style.display = tokenInput.value.trim() ? "" : "none";
    }

    updateShareXVisibility();

    if (refreshBtn) refreshBtn.addEventListener("click", async () => {
        if (!tokenInput) return;
        const haveLocal = !!tokenInput.value.trim();
        if (!haveLocal) {
            // Tentative de création si absent côté serveur
            const res = await fetch("/api/me/token/refresh", { method: "POST" });
            const data = await safeJSON(res);
            if (res.ok && data.token) {
                tokenInput.value = data.token;
                try { localStorage.setItem(LOCAL_TOKEN_KEY, data.token); } catch { }
                updateShareXVisibility();
                toast('Token créé', { type: 'success' });
                loadTokenMeta();
                updateTokenControls();
            } else if (res.ok && data.already) {
                // Token existe côté serveur mais on ne l'a pas localement
                if (confirm("Un token existe déjà mais n'est plus visible (sécurité). Le régénérer ?")) {
                    const r2 = await fetch("/api/me/token/refresh?rotate=1", { method: "POST" });
                    const d2 = await safeJSON(r2);
                    if (r2.ok && d2.token) {
                        tokenInput.value = d2.token;
                        try { localStorage.setItem(LOCAL_TOKEN_KEY, d2.token); } catch { }
                        updateShareXVisibility();
                        toast('Nouveau token généré', { type: 'success' });
                        loadTokenMeta();
                        updateTokenControls();
                    } else {
                        toast(d2.error || 'Erreur génération', { type: 'error' });
                        alert(d2.error || 'Erreur lors de la génération');
                    }
                }
            } else {
                toast(data.error || 'Erreur génération token', { type: 'error' });
                alert(data.error || 'Erreur lors de la génération');
            }
        } else {
            // On a déjà un token local -> proposer rotation
            if (!confirm("Régénérer le token ? L'ancien sera invalide. (Cooldown 60s)")) return;
            const res = await fetch("/api/me/token/refresh?rotate=1", { method: "POST" });
            const data = await safeJSON(res);
            if (res.ok && data.token) {
                tokenInput.value = data.token;
                try { localStorage.setItem(LOCAL_TOKEN_KEY, data.token); } catch { }
                updateShareXVisibility();
                toast('Token régénéré', { type: 'success' });
                loadTokenMeta();
                updateTokenControls();
            } else {
                toast(data.error || 'Erreur régénération token', { type: 'error' });
                alert(data.error || 'Erreur lors de la régénération');
            }
        }
    });

    if (revokeBtn) revokeBtn.addEventListener('click', async () => {
        if (!confirm('Révoquer ce token ? Il sera immédiatement invalide.')) return;
        const r = await fetch('/api/me/token/revoke', { method: 'POST' });
        const d = await safeJSON(r);
        if (r.ok && d.ok) {
            tokenInput.value = '';
            try { localStorage.removeItem(LOCAL_TOKEN_KEY); } catch { }
            updateShareXVisibility();
            if (tokenMetaBox) tokenMetaBox.style.display = 'none';
            if (revokeBtn) revokeBtn.style.display = 'none';
            toast('Token révoqué', { type: 'info' });
            updateTokenControls();
        } else {
            toast(d.error || 'Erreur révocation', { type: 'error' });
            alert(d.error || 'Erreur lors de la révocation');
        }
    });

    if (copyBtn && tokenInput) {
        copyBtn.addEventListener("click", () => {
            const wasHidden = tokenInput.type === "password";
            if (wasHidden) { try { tokenInput.type = "text"; } catch { } }
            tokenInput.select();
            document.execCommand("copy");
            if (wasHidden) { try { tokenInput.type = "password"; } catch { } }
            toast('Token copié', { type: 'success' });
        });
    }

    // Télécharger config ShareX
    on("downloadShareXBtn", "click", () => {
        const token = (tokenInput ? tokenInput.value.trim() : "");
        if (!token) return alert("Token introuvable");
        const sharexConfig = {
            Version: "18.0.1",
            Name: "MDuckPix",
            DestinationType: "ImageUploader",
            RequestMethod: "POST",
            RequestURL: BASE_URL + "/api/upload",
            Body: "MultipartFormData",
            FileFormName: "file",
            Headers: { Authorization: `Bearer ${token}` },
            ResponseType: "Json",
            URL: BASE_URL + "{json:url}",
            ThumbnailURL: BASE_URL + "{json:url}",
            ErrorMessage: "{json:error}"
        };
        const blob = new Blob([JSON.stringify(sharexConfig, null, 4)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url; a.download = "MDuckCDN.sxcu";
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });

    // === Déconnexion ===
    on("logoutBtn", "click", async () => { await fetch("/api/logout", { method: "POST" }); /* Conservation du token dans localStorage */ location.href = "/"; });

    // Charger métadonnées si un token (serveur) existe même si pas en clair
    loadTokenMeta();
});