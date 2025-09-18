function qs(param) { return new URL(location.href).searchParams.get(param); }
function setMsg(msg, type = '') {
    const el = document.getElementById('resetMsg'); if (!el) return;
    el.textContent = msg; el.className = type ? `msg ${type}` : 'muted';
}

document.addEventListener('DOMContentLoaded', () => {
    const token = qs('token');
    if (!token) {
        setMsg('Lien invalide ou expiré.');
        const form = document.getElementById('resetForm'); if (form) form.style.display = 'none';
        return;
    }
    const form = document.getElementById('resetForm');
    // Gestion des boutons œil par champ
    document.querySelectorAll('.pw-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const input = targetId ? document.getElementById(targetId) : null;
            if (!input) return;
            const visible = input.getAttribute('type') === 'text';
            input.setAttribute('type', visible ? 'password' : 'text');
            btn.setAttribute('aria-pressed', (!visible).toString());
        });
    });
    form?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const pwd = (document.getElementById('password') || {}).value || '';
        const pwd2 = (document.getElementById('password2') || {}).value || '';
        if (pwd.length < 8) { setMsg('Mot de passe trop court (min 8).', 'error'); return; }
        if (pwd !== pwd2) { setMsg('Les mots de passe ne correspondent pas.', 'error'); return; }
        try {
            const r = await fetch('/api/password/reset/confirm', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token, password: pwd }) });
            const j = await r.json().catch(() => ({}));
            if (r.ok && j && j.ok) {
                setMsg('Mot de passe mis à jour. Redirection vers la connexion…', 'success');
                form.reset();
                setTimeout(() => { location.href = '/login.html'; }, 1200);
            }
            else { setMsg(j && j.error ? j.error : 'Échec de la réinitialisation.', 'error'); }
        } catch { setMsg('Erreur réseau', 'error'); }
    });
});
