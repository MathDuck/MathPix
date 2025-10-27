async function fetchSession() {
    try { const r = await fetch("/api/session"); return await r.json(); } catch { return {}; }
}

function roleExplain(sess) {
    const role = sess.role;
    const label = sess.role_label || role;
    const q = sess.quotas || {};
    const daily = q.daily == null ? 'illimité' : q.daily + ' / jour';
    const cd = q.cooldownSec == null ? 'aucun cooldown' : `cooldown ${q.cooldownSec}s`;
    function autoDeleteLabel(sec) {
        if (sec == null) return role === 'anon' ? 'suppression après 15 jours sans accès' : 'pas de suppression auto';
        const d = Math.round(sec / 86400);
        if (d === 7) return 'suppression après 7 jours';
        if (d === 365 || d === 366) return 'suppression après 1 an';
        if (d % 30 === 0) return `suppression après ${d / 30} mois`;
        return `suppression après ${d} jours`;
    }
    const del = autoDeleteLabel(q.autoDeleteSec);
    return `${label}: ${daily} (${cd}, ${del})`;
}

document.addEventListener("DOMContentLoaded", async () => {
    let BASE_URL = (location.hostname === '127.0.0.1' || location.hostname === 'localhost')
        ? 'http://127.0.0.1:8787'
        : 'https://cdn.mduck.fr';
    try { window.__BASE_URL = BASE_URL; } catch { }
    const uploadZone = document.getElementById("uploadZone");
    if (uploadZone) uploadZone.classList.add("zone-loading");
    if (!window.__sessionPromise) {
        window.__sessionPromise = fetchSession().then(d => { window.__sessionData = d; return d; });
    }
    const sess = await window.__sessionPromise;
    try { window.dispatchEvent(new CustomEvent('session-ready', { detail: sess })); } catch { }
    const explainEl = document.getElementById("explain");
    if (explainEl) explainEl.textContent = roleExplain(sess.user_id ? sess : { role: 'anon', role_label: sess.role_label, quotas: sess.quotas });
    if (uploadZone) uploadZone.classList.remove("zone-loading");

    const fileInput = document.getElementById("fileInput");
    const chooseBtn = document.getElementById("chooseBtn");
    const previewContainer = document.getElementById("previewContainer");

    const toast = (m, o) => { if (window.__toast) window.__toast(m, o); };
    const safeJson = async (r) => { try { return await r.clone().json(); } catch { return {}; } };
    function handleCooldown(waitSeconds) {
        if (typeof waitSeconds !== 'number') return;
        if (window.__toastCountdown) window.__toastCountdown(waitSeconds, { message: 'Merci de patienter pendant {s}s' });
        else toast('Cooldown ' + waitSeconds + 's', { type: 'error', ttl: 4000 });
    }
    function handleUploadError(card, message, wait) {
        card.setError(message);
        if (message === 'Cooldown actif') handleCooldown(wait);
        else toast(message, { type: 'error' });
    }

    const formatBytes = (v) => (window.formatBytesProxy ? window.formatBytesProxy(v) : window.formatBytes(v));

    window.copyToClipboard = function (text) {
        try {
            navigator.clipboard.writeText(text).then(() => {
                toast('Lien copié', { type: 'success' });
            }).catch(() => {
                toast('Echec de copie', { type: 'error' });
            });
        } catch (_) {
            const ta = document.createElement('textarea');
            ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
            toast('Lien copié', { type: 'success' });
        }
    };

    function createPreviewCard(opts) {
        const { file, name, size, controller } = opts;
        const card = document.createElement('div');
        card.className = 'image-preview';

        const closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'preview-close';
        closeBtn.setAttribute('aria-label', 'Fermer l\'aperçu');
        closeBtn.innerHTML = '&times;';
        closeBtn.addEventListener('click', () => {
            if (controller) {
                try { controller.abort(); } catch (_) { }
            }
            card.remove();
        });
        card.appendChild(closeBtn);

        const imgWrap = document.createElement('div');
        imgWrap.className = 'image-container';
        const img = document.createElement('img');
        img.alt = 'Preview';
        if (file) {
            img.src = URL.createObjectURL(file);
        } else {
            img.src = '/images/placeholder.png'; // fallback (assure-toi d'avoir un placeholder si besoin)
        }
        imgWrap.appendChild(img);

        const overlay = document.createElement('div');
        overlay.className = 'loading-overlay';
        overlay.style.display = 'flex';
        overlay.style.alignItems = 'center';
        overlay.style.justifyContent = 'center';
        overlay.innerHTML = '<div class="spinner"></div>';
        imgWrap.appendChild(overlay);

        const info = document.createElement('div');
        info.className = 'image-info';
        const title = document.createElement('strong');
        title.textContent = name || (file ? file.name : 'image');
        const meta = document.createElement('span');
        meta.textContent = formatBytes(size ?? (file ? file.size : undefined));
        info.appendChild(title);
        info.appendChild(meta);

        const result = document.createElement('div');
        result.className = 'upload-result';
        result.style.display = 'none';
        info.appendChild(result);

        card.appendChild(imgWrap);
        card.appendChild(info);
        previewContainer.prepend(card);

        return {
            setSuccess(url) {
                overlay.remove();
                result.style.display = '';
                result.innerHTML = '';
                const input = document.createElement('input');
                input.type = 'text';
                const displayUrl = /^https?:/i.test(url) ? url : `${BASE_URL}${url}`;
                input.value = displayUrl;
                input.readOnly = true;
                input.onclick = () => input.select();
                input.classList.add('upload-url-input');
                const actions = document.createElement('div');
                actions.style.display = 'flex';
                actions.style.gap = '0.4rem';
                actions.style.flexShrink = '0';

                const copyBtn = document.createElement('button');
                copyBtn.className = 'btn btn-primary upload-copy-btn';
                copyBtn.textContent = '📋 Copier';
                copyBtn.addEventListener('click', () => { window.copyToClipboard(displayUrl); copyBtn.textContent = '✅ Copier'; setTimeout(() => copyBtn.textContent = '📋 Copier', 1200); });

                const openBtn = document.createElement('button');
                openBtn.type = 'button';
                openBtn.className = 'btn btn-primary upload-open-btn';
                openBtn.title = 'Ouvrir dans un nouvel onglet';
                openBtn.setAttribute('aria-label', 'Ouvrir l\'image dans un nouvel onglet');
                openBtn.innerHTML = '👁️\u00A0Ouvrir';
                openBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    try { window.open(displayUrl, '_blank', 'noopener,noreferrer'); } catch (_) { location.href = displayUrl; }
                });

                actions.appendChild(openBtn);
                actions.appendChild(copyBtn);

                result.appendChild(input);
                result.appendChild(actions);
            },
            setError(message) {
                overlay.innerHTML = '<div style="color:#f87171; font-size:0.8rem; text-align:center; padding:0.5rem;">' + (message || 'Erreur') + '</div>';
            }
        };
    }

    async function uploadFile(file) {
        const controller = new AbortController();
        const card = createPreviewCard({ file, controller });
        const formData = new FormData(); formData.append('file', file);
        try {
            const response = await fetch('/api/upload', { method: 'POST', body: formData, signal: controller.signal });
            const responseData = await response.json();
            if (!response.ok) {
                const msg = responseData.error || "Échec de l'upload";
                handleUploadError(card, msg, responseData.wait);
                return;
            }
            card.setSuccess(responseData.url);
            toast('Image uploadée', { type: 'success' });
        } catch (e) {
            if (e && e.name === 'AbortError') return;
            card.setError('Erreur réseau');
            toast('Erreur réseau', { type: 'error' });
        }
    }

    async function uploadFromUrl(url) {
        const parsedName = (() => { try { const parsedUrlObj = new URL(url); return parsedUrlObj.pathname.split('/').pop() || 'remote'; } catch (_) { return 'remote'; } })();
        const controller = new AbortController();
        const card = createPreviewCard({ file: null, name: parsedName, size: undefined, controller });
        try {
            const response = await fetch('/api/upload', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url }), signal: controller.signal });
            const responseData = await response.json();
            if (!response.ok) {
                const msg = responseData.error || 'Import impossible';
                handleUploadError(card, msg, responseData.wait);
                return;
            }
            card.setSuccess(responseData.url);
            toast('Image importée', { type: 'success' });
        } catch (e) {
            if (e && e.name === 'AbortError') return;
            card.setError('Erreur réseau');
            toast('Erreur réseau', { type: 'error' });
        }
    }

    if (chooseBtn && fileInput) {
        chooseBtn.addEventListener("click", () => fileInput.click());
        fileInput.addEventListener("change", () => {
            for (const file of fileInput.files) uploadFile(file);
        });
    }

    if (uploadZone) {
        uploadZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            uploadZone.classList.add("dragover");
        });
        uploadZone.addEventListener("dragleave", () => {
            uploadZone.classList.remove("dragover");
        });
        uploadZone.addEventListener("drop", (e) => {
            e.preventDefault();
            uploadZone.classList.remove("dragover");
            for (const file of e.dataTransfer.files) uploadFile(file);
        });
    }

    document.addEventListener("paste", (e) => {
        const entry = Array.from(e.clipboardData.items).find(entry => entry.type.startsWith("image/"));
        if (entry) {
            uploadFile(entry.getAsFile());
            return;
        }
        const text = e.clipboardData.getData("text");
        if (text && /\.(png|jpe?g|webp|avif)$/i.test(text)) {
            uploadFromUrl(text.trim());
        }
    });
});