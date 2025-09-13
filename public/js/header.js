function setupDropdown() {
    const dropdown = document.getElementById('userDropdown');
    const trigger = document.getElementById('userTrigger');
    if (!dropdown || !trigger) return;
    if (trigger.dataset.dropdownBound) return;
    trigger.dataset.dropdownBound = '1';
    trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdown.classList.toggle('open');
    });
    document.addEventListener('click', () => dropdown.classList.remove('open'));
    document.addEventListener('keydown', e => { if (e.key === 'Escape') dropdown.classList.remove('open'); });
}

async function initHeader() {
    const auth = document.getElementById('authButtons');
    const logged = document.getElementById('userLogged');
    if (!auth || !logged) return;
    try {
        if (!window.__sessionPromise) {
            window.__sessionPromise = fetch('/api/session', { credentials: 'include' })
                .then(r => r.json())
                .then(d => { window.__sessionData = d; try { window.dispatchEvent(new CustomEvent('session-ready', { detail: d })); } catch { } return d; })
                .catch(() => ({}));
        }
        const sessionInfo = window.__sessionData ? window.__sessionData : await window.__sessionPromise;
        if (!sessionInfo.user_id) {
            auth.style.display = '';
            logged.style.display = 'none';
            document.body.classList.add('auth-ready');
            return;
        }
        auth.style.display = 'none';
        logged.style.display = '';
        document.body.classList.add('auth-ready');
        const name = sessionInfo.username || sessionInfo.email || 'Compte';
        const headerUsername = document.getElementById('headerUsername');
        const menuUsername = document.getElementById('menuUsername');
        const menuRole = document.getElementById('menuRole');
        if (headerUsername) headerUsername.textContent = name;
        if (menuUsername) menuUsername.textContent = name;
        if (menuRole) {
            const label = sessionInfo.role_label || sessionInfo.role;
            menuRole.textContent = label;
            menuRole.className = 'role-badge role-' + sessionInfo.role;
        }
        function setAvatar(el, url) {
            if (!el) return;
            el.innerHTML = '';
            if (url) {
                const img = document.createElement('img');
                img.src = url; img.className = 'avatar-img';
                el.appendChild(img);
            } else {
                el.textContent = name.slice(0, 1).toUpperCase();
            }
        }
        setAvatar(document.getElementById('headerAvatar'), sessionInfo.avatar_url);
        setAvatar(document.getElementById('menuAvatar'), sessionInfo.avatar_url);
        const menuItems = document.getElementById('menuItems');
        if (menuItems && !menuItems.dataset.built) {
            const iconSettings = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15a3 3 0 1 1 0-6 3 3 0 0 1 0 6Z"/><path d="M19.4 12a7.4 7.4 0 0 0-.1-1l2.1-1.65-2-3.46-2.49 1a7.6 7.6 0 0 0-1.73-1L14.7 3h-5.4l-.58 2.89a7.6 7.6 0 0 0-1.73 1l-2.49-1-2 3.46L4.6 11c-.05.33-.1.66-.1 1s.05.67.1 1l-2.1 1.65 2 3.46 2.49-1c.52.43 1.1.78 1.73 1l.58 2.89h5.4l.58-2.89c.63-.22 1.21-.57 1.73-1l2.49 1 2-3.46L19.3 13c.05-.33.1-.66.1-1Z"/></svg>';
            const iconAdmin = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 2 3.09 6.26L22 9l-5 5 1.18 7L12 17.77 5.82 21 7 14 2 9l6.91-.74L12 2Z"/></svg>';
            const iconLogout = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>';
            const items = [];
            items.push({ type: 'link', href: '/settings', label: 'Paramètres', icon: iconSettings });
            if (sessionInfo.role === 'admin') items.push({ type: 'link', href: '/admin', label: 'Administration', icon: iconAdmin, target: '_blank' });
            items.push({ type: 'divider' });
            items.push({ type: 'button', id: 'logoutBtn', label: 'Déconnexion', icon: iconLogout, danger: true });
            for (const it of items) {
                if (it.type === 'divider') { const d = document.createElement('div'); d.className = 'menu-divider'; menuItems.appendChild(d); continue; }
                let el;
                if (it.type === 'link') { el = document.createElement('a'); el.href = it.href; if (it.target) { el.target = it.target; el.rel = 'noopener'; } }
                else { el = document.createElement('button'); el.type = 'button'; }
                el.className = 'menu-item' + (it.danger ? ' logout-item' : '');
                if (it.id) el.id = it.id;
                el.innerHTML = it.icon + '<span>' + it.label + '</span>';
                menuItems.appendChild(el);
            }
            menuItems.dataset.built = '1';
            const logout = document.getElementById('logoutBtn');
            if (logout) logout.addEventListener('click', async () => { await fetch('/api/logout', { method: 'POST' }); location.href = '/'; });
        }
        setupDropdown();
    } catch (e) { document.body.classList.add('auth-ready'); /* silencieux */ }
}
document.addEventListener('DOMContentLoaded', initHeader);
window.addEventListener('session-ready', (ev) => {
    if (document.body.classList.contains('auth-ready')) return;
    initHeader();
});
queueMicrotask(setupDropdown);
