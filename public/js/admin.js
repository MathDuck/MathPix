// Admin panel JS – version nettoyée + helpers unifiés

// --- Auth ---
// Récupère la session et s'assure que l'utilisateur est admin
async function mustAdmin() {
    try {
        const r = await fetch('/api/session');
        const sessionInfo = await r.json();
        if (sessionInfo.role !== 'admin') location.href = '/';
        return sessionInfo;
    } catch (e) {
        toast('Erreur réseau (session)', { type: 'error' });
        setTimeout(() => location.href = '/', 1200);
        return {};
    }
}

// --- State ---
// Limites fixes (20) + logs
let usersPage = 1, usersLimit = 20; let imagesPage = 1, imagesLimit = 20; let logsPage = 1, logsLimit = 20; let ipPage = 1, ipLimit = 20; let currentUserId = null;
const loadedSections = new Set();
const loaders = { dashboard: loadDashboard, users: loadUsers, images: loadAllImages, ip: loadIPs, logs: loadLogs, maintenance: () => { loadMaintHistory(); }, roles: loadRolePolicies };

// --- Utils partagées ---
const formatBytes = (v) => (window.formatBytesProxy ? window.formatBytesProxy(v) : (window.formatBytes ? window.formatBytes(v) : (v + ' B')));
const numFmt = new Intl.NumberFormat('fr-FR');
const __dateFmt = new Intl.DateTimeFormat('fr-FR', { dateStyle: 'short', timeStyle: 'medium' });
const fmtDate = (tsSec) => tsSec ? __dateFmt.format(new Date(tsSec * 1000)) : '';
let __dashPrev = { statsHash: '', recentHash: '', ipsHash: '' };
let __maintHistoryTimer = null;
const __optimCache = new Map();
const escapeHtml = (value) => (window.escapeHtml ? window.escapeHtml(value) : String(value));
const $ = (id) => document.getElementById(id);
const toast = (m, o) => { if (window.__toast) window.__toast(m, o); };
const safeJson = async (resp) => { try { return await resp.clone().json(); } catch { return {}; } };
const fetchJson = async (url, opts) => { const r = await fetch(url, opts); const j = await safeJson(r); return { ok: r.ok, status: r.status, json: j }; };
const confirmAction = (msg) => window.confirm(msg);
const DASH_CACHE_TTL = 10000;
let __dashCache = { data: null, ts: 0 };

document.addEventListener('DOMContentLoaded', async () => { const sess = await mustAdmin(); currentUserId = sess.user_id || null; initNav(); await loadDashboard(); });

function initNav() {
    const nav = document.getElementById('adminNav');
    nav.querySelectorAll('.admin-nav-item').forEach(btn => {
        btn.addEventListener('click', async () => {
            const section = btn.dataset.section;
            nav.querySelectorAll('.admin-nav-item').forEach(b => b.classList.toggle('active', b === btn));
            document.querySelectorAll('.admin-section').forEach(sec => sec.classList.toggle('active', sec.id === 'section-' + section));
            if (!loadedSections.has(section) && loaders[section]) { await loaders[section](); loadedSections.add(section); }
            if (section === 'maintenance') {
                loadMaintHistory();
                loadDbBackups();
                if (__maintHistoryTimer) clearInterval(__maintHistoryTimer);
                __maintHistoryTimer = setInterval(() => { if (document.getElementById('section-maintenance')?.classList.contains('active')) loadMaintHistory(); }, 60000);
            } else if (__maintHistoryTimer) { clearInterval(__maintHistoryTimer); __maintHistoryTimer = null; }
        });
    });
    const bind = (id, fn) => { const el = document.getElementById(id); if (el) el.addEventListener('click', fn); };
    bind('searchBtn', () => loadUsers($('searchUser').value.trim()));
    bind('imgSearchBtn', loadAllImages); bind('ipSetBtn', setIpScore); bind('logSearchBtn', loadLogs); bind('cleanupBtn', doCleanup);
    bind('purgeSessionsBtn', maintPurgeSessions);
    bind('purgeLogsBtn', maintPurgeLogs);
    bind('recalcStatsBtn', maintRecalcStats);
    bind('decayIpBtn', maintDecayIp);
    bind('r2StatsBtn', maintR2Stats);
    bind('scanOrphansBtn', maintScanOrphans);
    bind('deleteOrphansBtn', maintDeleteOrphans);
    bind('refreshMaintHistoryBtn', loadMaintHistory);
    bind('testMailBtn', maintTestMail);
    bind('discordTestBtn', maintDiscordTest);
    bind('dbBackupBtn', maintDbBackupNow);
    bind('refreshBackupsBtn', loadDbBackups);
}

// --- Dashboard (refactor + optimisations) ---
async function loadDashboard(force = false) {
    const now = Date.now();
    if (!force && __dashCache.data && (now - __dashCache.ts) < DASH_CACHE_TTL) {
        renderDashboard(__dashCache.data);
        return;
    }
    try {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), 8000);
        const fetchOpts = { signal: controller.signal, headers: {} };
        if (__dashCache.etag) (fetchOpts.headers)['if-none-match'] = __dashCache.etag;
        const resp = await fetch('/api/admin/summary', fetchOpts);
        clearTimeout(t);
        if (resp.status === 304 && __dashCache.data) {
            renderDashboard(__dashCache.data);
            return;
        }
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        let data;
        try {
            data = await resp.json();
        } catch (e) {
            if (__dashCache.data) { renderDashboard(__dashCache.data); return; }
            throw e;
        }
        __dashCache = { data, ts: now, etag: resp.headers.get('etag') || null };
        renderDashboard(__dashCache.data);
    } catch (e) { renderDashboardError(e); }
}

function renderDashboardError(err) {
    const grid = document.getElementById('dashStats'); if (grid) grid.innerHTML = `<div class="stat-tile error"><span class="stat-label">Erreur</span><span class="stat-value">${(err && err.message) || 'Chargement'}</span></div>`;
    const recent = document.getElementById('dashRecent'); if (recent) recent.innerHTML = '<div class="empty">Impossible de charger les données.</div>';
    const top = document.getElementById('dashTopIps'); if (top) top.innerHTML = '<tr><td colspan="2">Erreur</td></tr>';
}

function renderDashboard(data) {
    const safe = (o, d = {}) => o || d;
    const users = safe(data.users, { total: 0, active: 0, disabled: 0 });
    const images = safe(data.images, { total: 0, last24h: 0, last1h: 0, bytes_total: 0 });
    const audit = safe(data.audit, { last24h: 0 });
    const statsShape = {
        uT: users.total, uA: users.active, uD: users.disabled,
        iT: images.total, i24: images.last24h, i1: images.last1h, iB: images.bytes_total,
        l24: audit.last24h
    };
    const recentImages = Array.isArray(data.recent_images) ? data.recent_images : [];
    const topIps = (data.ip_blocks && Array.isArray(data.ip_blocks.top)) ? data.ip_blocks.top : [];
    const statsHash = JSON.stringify(statsShape);
    const recentHash = JSON.stringify(recentImages.map(i => [i.id, i.owner_username]));
    const ipsHash = JSON.stringify(topIps.map(i => [i.ip, i.score]));

    if (statsHash !== __dashPrev.statsHash) renderDashboardStats(statsShape);
    if (recentHash !== __dashPrev.recentHash) renderDashboardRecent(recentImages);
    if (ipsHash !== __dashPrev.ipsHash) renderDashboardTopIps(topIps);
    __dashPrev = { statsHash, recentHash, ipsHash };
}

function renderDashboardStats(stats) {
    const grid = document.getElementById('dashStats'); if (!grid) return;
    const tiles = [
        ['Utilisateurs', stats.uT], ['Actifs', stats.uA], ['Désactivés', stats.uD],
        ['Images', stats.iT], ['Images 24h', stats.i24], ['Images 1h', stats.i1], ['Stock total', formatBytes(stats.iB)], ['Logs 24h', stats.l24]
    ];
    const frag = document.createDocumentFragment();
    tiles.forEach(([label, value]) => {
        const div = document.createElement('div');
        div.className = 'stat-tile';
        div.innerHTML = `<span class="stat-label">${label}</span><span class="stat-value">${typeof value === 'number' && label !== 'Stock total' ? numFmt.format(value) : value}</span>`;
        frag.appendChild(div);
    });
    grid.innerHTML = '';
    grid.appendChild(frag);
}

function renderDashboardRecent(list) {
    const recent = document.getElementById('dashRecent'); if (!recent) return;
    recent.classList.add('list');
    recent.innerHTML = '';
    const header = document.createElement('div');
    header.className = 'recent-row recent-header';
    header.innerHTML = '<div class="recent-cell-id">ID</div><div class="recent-cell-user">User (id)</div><div class="recent-cell-date">Date</div><div class="recent-cell-actions">Actions</div>';
    recent.appendChild(header);
    if (!list.length) {
        const empty = document.createElement('div'); empty.className = 'recent-row empty'; empty.textContent = 'Aucune image récente.'; recent.appendChild(empty); return;
    }
    const frag = document.createDocumentFragment();
    list.forEach(img => {
        const row = document.createElement('div');
        row.className = 'recent-row';
        row.dataset.id = img.id; row.dataset.url = img.url; row.dataset.ext = img.ext || ''; row.dataset.size = img.size || 0;
        if (img.original_name) row.dataset.originalName = img.original_name;
        const uname = img.owner_username || 'Anonyme';
        const created = fmtDate(img.created_at);
        const apiBadge = img.via_api ? `<span class='api-badge' title='Upload via API token'>API</span>` : '';
        const adminUrl = img.url + (img.url.includes('?') ? '&' : '?') + 'no_track=1&source=admin';
        row.innerHTML = `<div class="recent-cell-id">${img.id}${apiBadge}</div><div class="recent-cell-user">${uname}${img.owner_id ? `<br><span class='muted'>${img.owner_id}</span>` : ''}</div><div class="recent-cell-date" data-optim-target="${img.id}">${created}</div><div class="recent-cell-actions"><button type="button" class="btn btn-secondary btn-xs" data-act="open">Voir</button><a href="${adminUrl}" class="btn btn-primary btn-xs" target="_blank" rel="noopener" data-act="direct">Ouvrir</a></div>`;
        row.addEventListener('click', e => { if (e.target.getAttribute && e.target.getAttribute('data-act') === 'open') openLightbox({ id: img.id, url: adminUrl, ext: img.ext, size: img.size, original_name: img.original_name, last_access_at: img.last_access_at }); });
        frag.appendChild(row);
    });
    recent.appendChild(frag);
    enrichOptimBadges([...recent.querySelectorAll('[data-optim-target]')].map(el => el.getAttribute('data-optim-target')));
}

function renderDashboardTopIps(list) {
    const top = document.getElementById('dashTopIps'); if (!top) return;
    top.innerHTML = '';
    if (!list.length) { top.innerHTML = '<tr><td colspan="2">Aucune donnée</td></tr>'; return; }
    const frag = document.createDocumentFragment();
    list.forEach(ip => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${ip.ip}</td><td>${ip.score || 0}</td><td>${fmtDate(ip.updated_at)}</td><td>${ip.owner || 'Inconnu'}</td>`;
        frag.appendChild(tr);
    });
    top.appendChild(frag);
}

// --- Users ---
async function loadUsers(searchQuery) {
    const params = new URLSearchParams(); params.set('page', usersPage); params.set('limit', usersLimit); if (searchQuery) params.set('q', searchQuery);
    const { json: data } = await fetchJson('/api/admin/users?' + params.toString());
    const tbody = $('usersBody'); tbody.innerHTML = '';
    let rolePoliciesCache = window.__rolePoliciesCache;
    let rolePoliciesMap = window.__rolePoliciesMap;
    if (!rolePoliciesCache || !rolePoliciesMap) {
        try { const rp = await fetchJson('/api/admin/role-policies'); if (rp.ok) { const arr = rp.json.policies || []; rolePoliciesCache = arr.map(p => p.role); rolePoliciesMap = {}; arr.forEach(p => { rolePoliciesMap[p.role] = (p.label && p.label.trim()) || p.role; }); window.__rolePoliciesCache = rolePoliciesCache; window.__rolePoliciesMap = rolePoliciesMap; } } catch { rolePoliciesCache = []; rolePoliciesMap = {}; }
    }
    (data.users || []).forEach(userRow => {
        const tr = document.createElement('tr');
        if (userRow.id === currentUserId) tr.classList.add('self-user');
        const roles = rolePoliciesCache || [];
        const optionsHtml = roles.map(r => `<div class="role-option${userRow.role === r ? ' active' : ''}" data-value="${r}" role="option" aria-selected="${userRow.role === r}" tabindex="0"><span class="role-badge-dot"></span><span>${rolePoliciesMap[r] || r}</span></div>`).join('');
        const roleLabel = (rolePoliciesMap && rolePoliciesMap[userRow.role]) ? rolePoliciesMap[userRow.role] : userRow.role;
        tr.innerHTML = `<td>${userRow.id}</td><td>${userRow.username || '-'}</td><td>${userRow.email}</td><td>
        <div class="role-select" data-id="${userRow.id}">
            <button type="button" class="role-trigger" data-role="${userRow.role}" aria-haspopup="listbox" aria-expanded="false" ${userRow.id === currentUserId ? 'disabled aria-disabled="true" data-self="1"' : ''}><span class="role-badge-dot"></span><span class="role-label">${roleLabel}${userRow.id === currentUserId ? ' (vous)' : ''}</span><span class="chevron">▾</span></button>
            <div class="role-menu" role="listbox" aria-label="Changer rôle">${optionsHtml}</div></div></td><td>${userRow.disabled ? 'désactivé' : 'actif'}</td><td><button class="btn btn-secondary btn-xs toggle" data-id="${userRow.id}" data-disabled="${userRow.disabled ? 0 : 1}">${userRow.disabled ? 'Activer' : 'Désactiver'}</button></td>`;
        tbody.appendChild(tr);
    });
    buildUsersPagination(data.pages || 1, data.page || 1);
    tbody.querySelectorAll('.toggle').forEach(btn => {
        const id = btn.getAttribute('data-id');
        if (id && id === String(currentUserId)) { btn.disabled = true; btn.title = 'Action désactivée sur votre propre compte'; }
        btn.addEventListener('click', async e => { const targetUserId = e.currentTarget.getAttribute('data-id'); if (targetUserId === String(currentUserId)) return; const disabled = e.currentTarget.getAttribute('data-disabled') === '1'; await fetch('/api/admin/user/disable', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: targetUserId, disabled }) }); loadUsers($('searchUser').value.trim()); toast('Statut mis à jour', { type: 'success' }); });
    });
    initRoleDropdowns(tbody);
}
function buildUsersPagination(pages, current) { const c = ensurePagination('usersPagination'); c.dataset.pagerFor = 'users'; c.innerHTML = renderPager({ pages, current }); }

// --- Role dropdown ---
function initRoleDropdowns(scope) {
    const selects = scope.querySelectorAll('.role-select');
    selects.forEach(sel => {
        const trigger = sel.querySelector('.role-trigger'); const menu = sel.querySelector('.role-menu'); if (!trigger || !menu) return;
        function close() { sel.classList.remove('open'); trigger.setAttribute('aria-expanded', 'false'); }
        function open() { document.querySelectorAll('.role-select.open').forEach(o => { if (o !== sel) o.classList.remove('open'); }); sel.classList.add('open'); trigger.setAttribute('aria-expanded', 'true'); (menu.querySelector('.role-option.active') || menu.querySelector('.role-option')).focus(); }
        trigger.addEventListener('click', e => { e.stopPropagation(); sel.classList.contains('open') ? close() : open(); });
        trigger.addEventListener('keydown', e => { if (['Enter', ' '].includes(e.key)) { e.preventDefault(); sel.classList.contains('open') ? close() : open(); } else if (e.key === 'ArrowDown') { e.preventDefault(); if (!sel.classList.contains('open')) open(); else { const act = menu.querySelector(':focus') || menu.querySelector('.role-option.active'); const nxt = (act && act.nextElementSibling) || menu.querySelector('.role-option'); nxt && nxt.focus(); } } else if (e.key === 'ArrowUp') { e.preventDefault(); if (!sel.classList.contains('open')) open(); else { const act = menu.querySelector(':focus') || menu.querySelector('.role-option.active'); const prev = (act && act.previousElementSibling) || [...menu.querySelectorAll('.role-option')].pop(); prev && prev.focus(); } } else if (e.key === 'Escape') { close(); } });
        async function apply(opt) { const value = opt.getAttribute('data-value'); const userId = sel.getAttribute('data-id'); if (!value || !userId) return; if (opt.classList.contains('active')) { close(); trigger.focus(); return; } const r = await fetch('/api/admin/user/role', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: userId, role: value }) }); if (r.ok) { menu.querySelectorAll('.role-option').forEach(o => o.classList.remove('active')); opt.classList.add('active'); trigger.setAttribute('data-role', value); trigger.querySelector('.role-label').textContent = value; trigger.classList.remove('role-anim'); void trigger.offsetWidth; trigger.classList.add('role-anim'); window.__toast && window.__toast('Rôle mis à jour', { type: 'success' }); close(); trigger.focus(); } else { window.__toast && window.__toast('Échec rôle', { type: 'error' }); } }
        menu.querySelectorAll('.role-option').forEach(opt => { opt.addEventListener('click', e => { e.stopPropagation(); apply(opt); }); opt.addEventListener('keydown', e => { if (['Enter', ' '].includes(e.key)) { e.preventDefault(); apply(opt); } else if (e.key === 'Escape') { close(); trigger.focus(); } else if (e.key === 'ArrowDown') { e.preventDefault(); (opt.nextElementSibling || menu.querySelector('.role-option')).focus(); } else if (e.key === 'ArrowUp') { e.preventDefault(); (opt.previousElementSibling || [...menu.querySelectorAll('.role-option')].pop()).focus(); } }); });
    });
    document.addEventListener('click', e => { if (!e.target.closest('.role-select')) document.querySelectorAll('.role-select.open').forEach(o => o.classList.remove('open')); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') document.querySelectorAll('.role-select.open').forEach(o => o.classList.remove('open')); });
}

// --- Images ---
async function loadAllImages() {
    const imageIdFilter = $('imgSearchId').value.trim();
    const ownerFilter = $('imgSearchOwner').value.trim();
    const usernameFilter = ($('imgSearchUsername') || { value: '' }).value.trim();
    const params = new URLSearchParams();
    params.set('page', imagesPage); params.set('limit', imagesLimit);
    if (imageIdFilter) params.set('id', imageIdFilter);
    if (ownerFilter) params.set('owner', ownerFilter);
    if (usernameFilter) params.set('username', usernameFilter);
    const { json: data } = await fetchJson(`/api/admin/images?${params.toString()}`);
    const tbody = $('adminImagesBody'); tbody.innerHTML = '';
    const ids = [];
    (data.images || []).forEach(imageRow => {
        const imageUrl = `${location.origin}/i/${imageRow.id}${imageRow.ext}?no_track=1`;
        const ownerUsername = imageRow.owner_username || 'Anonyme';
        const tr = document.createElement('tr');
        const apiBadge = imageRow.via_api ? `<span class='api-badge' title='Upload via API token'>API</span>` : '';
        tr.innerHTML = `<td data-optim-target="${imageRow.id}">${imageRow.id}${apiBadge}</td><td>${imageRow.owner_id ? `${imageRow.owner_id}<br><span class='muted'>${ownerUsername}</span>` : 'Anonyme'}</td><td>${new Date(imageRow.created_at * 1000).toLocaleString()}</td><td><div class=\"btn-group-compact\"><button class=\"btn btn-secondary btn-xs view\" data-id=\"${imageRow.id}\" data-url=\"${imageUrl}\" data-ext=\"${imageRow.ext}\" data-size=\"${imageRow.size || 0}\" data-original-name=\"${(imageRow.original_name || '').replace(/\\"/g, '&quot;')}\" data-last-access=\"${imageRow.last_access_at || ''}\">Voir</button><button class=\"btn btn-error btn-xs del\" data-id=\"${imageRow.id}\">Suppr.</button></div></td>`;
        tbody.appendChild(tr);
        ids.push(imageRow.id);
    });
    buildImagesPagination(data.pages || 1, data.page || 1);
    tbody.querySelectorAll('.del').forEach(btn => btn.addEventListener('click', async e => {
        const targetImageId = e.currentTarget.getAttribute('data-id');
        if (!confirmAction(`Supprimer l'image ${targetImageId} ?`)) return;
        const resp = await fetch(`/api/image/${targetImageId}`, { method: 'DELETE' });
        if (resp.ok) { loadAllImages(); toast('Image supprimée', { type: 'success' }); }
        else toast('Échec suppression', { type: 'error' });
    }));
    tbody.querySelectorAll('.view').forEach(btn => btn.addEventListener('click', e => {
        const button = e.currentTarget;
        const la = button.getAttribute('data-last-access');
        const last_access_at = la ? parseInt(la, 10) : undefined;
        openLightbox({ id: button.getAttribute('data-id'), url: button.getAttribute('data-url'), ext: button.getAttribute('data-ext'), size: parseInt(button.getAttribute('data-size') || '0', 10), original_name: button.getAttribute('data-original-name') || undefined, last_access_at });
    }));
    enrichOptimBadges(ids);
}

// --- IP Blocks ---
async function loadIPs() { const params = new URLSearchParams(); params.set('page', ipPage); params.set('limit', ipLimit); const { json: result } = await fetchJson('/api/admin/ipblocks?' + params.toString()); const tb = $('ipBody'); tb.innerHTML = ''; (result.ips || []).forEach(ipRow => { const tr = document.createElement('tr'); tr.innerHTML = `<td>${ipRow.ip}</td><td>${ipRow.score}</td><td>${fmtDate(ipRow.updated_at)}</td>`; tb.appendChild(tr); }); buildIpPagination(result.pages || 1, result.page || 1); }
async function setIpScore() { const ip = $('ipAddr').value.trim(); const score = parseInt($('ipScore').value, 10); if (!ip || isNaN(score)) return; await fetch('/api/admin/ipblocks/set', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ip, score }) }); loadIPs(); }

// --- Logs ---
async function loadLogs() {
    const searchQuery = $('logQ').value.trim();
    const params = new URLSearchParams();
    params.set('page', logsPage);
    params.set('limit', logsLimit);
    if (searchQuery) params.set('q', searchQuery);
    const { json: result } = await fetchJson('/api/admin/logs?' + params.toString());
    const tbody = $('logBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    const list = Array.isArray(result.logs) ? result.logs : [];
    if (!list.length) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td colspan="6" class="muted">Aucun log</td>';
        tbody.appendChild(tr);
    } else {
        const frag = document.createDocumentFragment();
        list.forEach(l => {
            const tr = document.createElement('tr');
            const metaRaw = (l.meta !== undefined && l.meta !== null) ? l.meta : '';
            let metaFull = '';
            if (typeof metaRaw === 'string') metaFull = metaRaw;
            else if (typeof metaRaw === 'object') { try { metaFull = JSON.stringify(metaRaw); } catch { metaFull = '[meta]'; } }
            else metaFull = String(metaRaw || '');
            const metaShort = metaFull.length > 80 ? metaFull.slice(0, 80) + '…' : metaFull;
            const created = fmtDate(l.created_at);
            const esc = (s) => escapeHtml(s).replace(/\"/g, '&quot;');
            const uname = l.user_username ? escapeHtml(l.user_username) : '';
            const userCell = (l.user_id || uname) ? `${l.user_id || ''}${uname ? `<br><span class='muted'>${uname}</span>` : ''}` : 'Anonyme';
            tr.innerHTML = `<td>${l.id ?? ''}</td><td>${escapeHtml(l.type || '')}</td><td>${userCell}</td><td>${l.ip || ''}</td><td class=\"log-meta-cell\" title=\"${esc(metaFull)}\"><span class=\"code\">${escapeHtml(metaShort)}</span></td><td>${created}</td>`;
            frag.appendChild(tr);
        });
        tbody.appendChild(frag);
    }
    buildLogsPagination(result.pages || 1, result.page || 1);
}

// --- Maintenance ---
async function doCleanup() { if (!confirmAction('Lancer le nettoyage maintenant ?')) return; await fetch('/api/admin/cleanup', { method: 'POST' }); toast('Nettoyage lancé', { type: 'success' }); }
document.addEventListener('DOMContentLoaded', () => {
    const btn = $('cleanupBtn');
    if (btn) {
        const progress = $('cleanupProgress');
        const statusValue = $('cleanupStatusValue');
        btn.addEventListener('click', async () => {
            if (!confirmAction('Confirmer le nettoyage ?')) return;
            btn.disabled = true;
            const orig = btn.textContent;
            btn.textContent = 'En cours…';
            progress && (progress.hidden = false);
            statusValue && (statusValue.textContent = 'En cours');
            const started = Date.now();
            try {
                const resp = await fetch('/api/admin/cleanup', { method: 'POST' });
                const ok = resp.ok;
                const dur = ((Date.now() - started) / 1000).toFixed(1) + 's';
                statusValue && (statusValue.textContent = ok ? 'Terminé (' + dur + ')' : 'Erreur');
                toast(ok ? 'Nettoyage terminé' : 'Échec nettoyage', { type: ok ? 'success' : 'error' });
            } catch (e) {
                statusValue && (statusValue.textContent = 'Erreur réseau');
                toast('Erreur réseau', { type: 'error' });
            } finally {
                btn.disabled = false; btn.textContent = orig; progress && (progress.hidden = true);
            }
        });
    }
});

// --- Lightbox ---
function openLightbox(img) {
    const lb = $('lightbox'); if (!lb) return;
    const imgEl = $('lightboxImg'); const metaEl = $('lightboxMeta');
    imgEl.src = img.url;
    const safeOrigName = img.original_name ? escapeHtml(img.original_name) : '-';
    const idBadge = img.via_api ? `<span class='api-badge' title='Upload via API token'>API</span>` : '';
    const lastAccess = img.last_access_at ? __dateFmt.format(new Date(img.last_access_at * 1000)) : '—';
    metaEl.innerHTML = `
        <h3>Détails</h3>
        <div class='lb-row'><span class='lb-label'>ID</span><span class='lb-value'>${img.id} ${idBadge}</span></div>
        <div class='lb-row'><span class='lb-label'>Extension</span><span class='lb-value'>${img.ext || ''}</span></div>
        <div class='lb-row'><span class='lb-label'>Nom original</span><span class='lb-value'>${safeOrigName}</span></div>
        <div class='lb-row'><span class='lb-label'>Dernier accès</span><span class='lb-value'>${lastAccess}</span></div>
        <div class='lb-row'><span class='lb-label'>Taille</span><span class='lb-value' id='lb-size-orig'>${formatBytes(img.size || 0)}</span></div>
        <div class='lb-row'><span class='lb-label'>Taille finale</span><span class='lb-value' id='lb-size-final'>—</span></div>
        <div class='lb-row'><span class='lb-label'>Pourcentage</span><span class='lb-value' id='lb-size-pct'>—</span></div>
        <div class='lb-actions'>
            <button class='btn btn-secondary btn-xs' data-copy='url'>Copier URL</button>
            <a class='btn btn-primary btn-xs' href='${img.url}' target='_blank' rel='noopener'>Ouvrir</a>
        </div>`;
    lb.style.display = 'flex';
    const escHandler = e => { if (e.key === 'Escape') closeLightbox(); };
    document.addEventListener('keydown', escHandler);
    lb.dataset.esc = '1';
    lb.querySelectorAll('[data-close]').forEach(el => { el.onclick = () => closeLightbox(); });
    const copyBtn = metaEl.querySelector('[data-copy=url]');
    if (copyBtn) copyBtn.addEventListener('click', async () => { try { await navigator.clipboard.writeText(img.url); toast('URL copiée', { type: 'success' }); } catch { toast('Copie impossible', { type: 'error' }); } });
    function closeLightbox() { lb.style.display = 'none'; if (lb.dataset.esc) { document.removeEventListener('keydown', escHandler); delete lb.dataset.esc; } }
    lb.addEventListener('mousedown', e => { if (e.target.classList.contains('lightbox-backdrop')) closeLightbox(); }, { once: true });

    (async () => {
        try {
            const r = await fetch(`/api/admin/image/optim?id=${encodeURIComponent(img.id)}`);
            if (!r.ok) return;
            const j = await r.json();
            if (!j || !j.ok || !j.optim) return;
            const { original_bytes, final_bytes, saved_pct } = j.optim;
            const finalEl = document.getElementById('lb-size-final');
            const pctEl = document.getElementById('lb-size-pct');
            if (finalEl && final_bytes) finalEl.textContent = formatBytes(final_bytes);
            else if (finalEl) finalEl.textContent = document.getElementById('lb-size-orig')?.textContent || '—';
            if (pctEl) pctEl.textContent = (typeof saved_pct === 'number') ? saved_pct.toFixed(2) + '%' : '0%';
        } catch { /* ignore */ }
    })();
    // Fetch via_api flag if not provided
    if (img.via_api === undefined) {
        (async () => {
            try {
                const r = await fetch(`/api/admin/image/source?id=${encodeURIComponent(img.id)}`);
                if (!r.ok) return;
                const j = await r.json();
                if (j && j.ok && typeof j.via_api === 'boolean' && j.via_api) {
                    const idRow = metaEl.querySelector('.lb-row .lb-value');
                    if (idRow && !idRow.querySelector('.api-badge')) {
                        idRow.innerHTML = `${img.id} <span class='api-badge' title='Upload via API token'>API</span>`;
                    }
                }
            } catch { /* ignore */ }
        })();
    }
}

async function fetchOptim(id) {
    if (!id) return null;
    if (__optimCache.has(id)) return __optimCache.get(id);
    try {
        const r = await fetch(`/api/admin/image/optim?id=${encodeURIComponent(id)}`);
        if (!r.ok) { __optimCache.set(id, null); return null; }
        const j = await r.json();
        const v = (j && j.ok) ? j.optim : null;
        __optimCache.set(id, v);
        return v;
    } catch { __optimCache.set(id, null); return null; }
}

function enrichOptimBadges(ids) {
    if (!ids || !ids.length) return;
    const MAX_CONC = 4;
    let index = 0; let active = 0;
    const runNext = () => {
        if (index >= ids.length) return;
        while (active < MAX_CONC && index < ids.length) {
            const id = ids[index++];
            active++;
            fetchOptim(id).then(v => {
                if (v && typeof v.saved_pct === 'number' && v.saved_pct > 0) {
                    const targets = document.querySelectorAll(`[data-optim-target='${id}']`);
                    targets.forEach(el => {
                        if (el.querySelector('.opt-badge')) return;
                        const badge = document.createElement('span');
                        badge.className = 'opt-badge';
                        badge.textContent = `−${v.saved_pct.toFixed(2)}%`;
                        badge.style.padding = '0 4px';
                        badge.style.background = '#0a6';
                        badge.style.color = '#fff';
                        badge.style.borderRadius = '3px';
                        badge.style.fontSize = '11px';
                        badge.title = 'Réduction taille';
                        if (el.classList.contains('recent-cell-date')) { el.style.display = 'flex'; el.style.alignItems = 'center'; badge.style.marginLeft = 'auto'; } else { badge.style.marginLeft = '6px'; }
                        el.appendChild(badge);
                    });
                }
            }).finally(() => { active--; runNext(); });
        }
    };
    runNext();
}

// --- Pagination helpers ---
function ensurePagination(id) {
    let c = document.getElementById(id);
    if (!c) {
        c = document.createElement('div');
        c.id = id; c.className = 'pagination-bar';
        if (id === 'usersPagination') document.getElementById('section-users')?.appendChild(c);
        else if (id === 'imagesPagination') document.getElementById('section-images')?.appendChild(c);
        else if (id === 'logsPagination') document.getElementById('section-logs')?.appendChild(c);
        else if (id === 'ipPagination') document.getElementById('section-ip')?.appendChild(c);
    }
    return c;
}
function buildImagesPagination(pages, current) { const c = ensurePagination('imagesPagination'); c.dataset.pagerFor = 'images'; c.innerHTML = renderPager({ pages, current }); }
function buildLogsPagination(pages, current) { const c = ensurePagination('logsPagination'); c.dataset.pagerFor = 'logs'; c.innerHTML = renderPager({ pages, current }); }
function buildIpPagination(pages, current) { const c = ensurePagination('ipPagination'); c.dataset.pagerFor = 'ip'; c.innerHTML = renderPager({ pages, current }); }

// --- Pager rendering util (existant ailleurs ?) Fallback simple ---
// --- Advanced reusable pager ---
function renderPager({ pages, current, total }) {
    if (!pages || pages < 2) return '';
    const btn = (p, label = p, extra = '') => `<button type="button" class="pg-btn${p === current ? ' active' : ''}" data-page="${p}" ${p === current ? 'aria-current="page"' : ''} ${extra}>${label}</button>`;
    const items = [];
    // First
    items.push(btn(1, '«', current === 1 ? 'disabled aria-disabled="true"' : 'aria-label="Première page"'));
    // Prev
    items.push(btn(Math.max(1, current - 1), '‹', current === 1 ? 'disabled aria-disabled="true" aria-label="Page précédente"' : 'aria-label="Page précédente"'));
    const windowSize = 2;
    const addEllipsis = () => items.push('<span class="pg-ellipsis" aria-hidden="true">…</span>');
    const inWindow = (p) => p === 1 || p === pages || (p >= current - windowSize && p <= current + windowSize);
    let lastPrinted = 0;
    for (let p = 1; p <= pages; p++) {
        if (inWindow(p)) {
            if (p - lastPrinted > 1) addEllipsis();
            items.push(btn(p));
            lastPrinted = p;
        }
    }
    // Next
    items.push(btn(Math.min(pages, current + 1), '›', current === pages ? 'disabled aria-disabled="true" aria-label="Page suivante"' : 'aria-label="Page suivante"'));
    // Last
    items.push(btn(pages, '»', current === pages ? 'disabled aria-disabled="true" aria-label="Dernière page"' : 'aria-label="Dernière page"'));
    const info = `<span class="pg-info">Page ${current}/${pages}${total ? ' • ' + total + ' éléments' : ''}</span>`;
    return `<nav class="pager" role="navigation" aria-label="Pagination">${items.join('')} ${info}</nav>`;
}

// Event delegation (click pagination / change page size)
document.addEventListener('click', e => {
    const pageBtn = e.target.closest('.pg-btn'); if (!pageBtn) return;
    if (pageBtn.disabled || pageBtn.getAttribute('disabled') !== null) return;
    const newPage = parseInt(pageBtn.dataset.page, 10); if (isNaN(newPage)) return;
    const container = pageBtn.closest('[data-pager-for]'); if (!container) return;
    const target = container.dataset.pagerFor;
    if (target === 'users') { if (newPage !== usersPage) { usersPage = newPage; loadUsers($('searchUser').value.trim()); } }
    else if (target === 'images') { if (newPage !== imagesPage) { imagesPage = newPage; loadAllImages(); } }
    else if (target === 'logs') { if (newPage !== logsPage) { logsPage = newPage; loadLogs(); } }
    else if (target === 'ip') { if (newPage !== ipPage) { ipPage = newPage; loadIPs(); } }
});

// --- Maintenance actions supplément ---
async function maintPurgeSessions() { if (!confirmAction('Purger les sessions expirées + tokens inactifs ?')) return; const btn = $('purgeSessionsBtn'); btn.disabled = true; const { json } = await fetchJson('/api/admin/maint/purge-sessions', { method: 'POST' }); btn.disabled = false; toast(json.ok ? `Purge ok (sessions:${json.meta?.sessions || 0} tokens:${json.meta?.api_tokens || 0})` : 'Erreur purge', { type: json.ok ? 'success' : 'error' }); }
async function maintPurgeLogs() { const days = parseInt($('purgeLogsDays').value, 10); if (!confirmAction(`Supprimer les logs plus vieux que ${days} jours ?`)) return; const btn = $('purgeLogsBtn'); btn.disabled = true; const { json } = await fetchJson('/api/admin/maint/purge-logs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ days }) }); btn.disabled = false; toast(json.ok ? `Logs purgés: ${json.items || 0}` : 'Erreur purge logs', { type: json.ok ? 'success' : 'error' }); }
async function maintRecalcStats() { if (!confirmAction('Reconstruire la table users_stats ?')) return; const btn = $('recalcStatsBtn'); btn.disabled = true; const { json } = await fetchJson('/api/admin/maint/recalc-stats', { method: 'POST' }); btn.disabled = false; toast(json.ok ? `Stats reconstruites (${json.items || 0})` : 'Erreur recalc', { type: json.ok ? 'success' : 'error' }); }
async function maintDecayIp() { const btn = $('decayIpBtn'); btn.disabled = true; const { json } = await fetchJson('/api/admin/maint/decay-ip', { method: 'POST' }); btn.disabled = false; toast(json.ok ? 'Décroissance appliquée' : 'Erreur décroissance', { type: json.ok ? 'success' : 'error' }); loadIPs(); }
async function maintR2Stats() { const btn = $('r2StatsBtn'); btn.disabled = true; const { json } = await fetchJson('/api/admin/maint/r2-stats'); btn.disabled = false; if (json.images) { $('r2ImagesMeta').textContent = `${json.images.count} / ${formatBytes(json.images.total)}`; $('r2AvatarsMeta').textContent = `${json.avatars.count} / ${formatBytes(json.avatars.total)}`; toast('Stats R2 mises à jour', { type: 'success' }); } else { toast('Erreur stats R2', { type: 'error' }); } }
async function maintTestMail() { const btn = $('testMailBtn'); const to = ($('testMailTo') || { value: '' }).value.trim(); if (!confirmAction('Envoyer un email de test' + (to ? ' à ' + to : '') + ' ?')) return; btn.disabled = true; const { json } = await fetchJson('/api/admin/maint/test-mail', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(to ? { to } : {}) }); btn.disabled = false; if (json.ok) { toast('Email test envoyé', { type: 'success' }); loadMaintHistory(); } else { toast(json.error || 'Erreur test mail', { type: 'error' }); } }
async function maintDiscordTest() {
    const btn = $('discordTestBtn'); if (!btn) return; if (!confirmAction('Envoyer le message test Discord ?')) return; btn.disabled = true; const started = Date.now(); const payload = { message: "I'm a test" }; const { json } = await fetchJson('/api/admin/discord/test', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) }); btn.disabled = false; const dur = ((Date.now() - started) / 1000).toFixed(1) + 's'; const statusEl = $('discordTestStatus'); if (json.ok) { toast('Webhook envoyé', { type: 'success' }); statusEl && (statusEl.textContent = 'OK (' + dur + ')'); } else { toast(json.error || 'Échec webhook', { type: 'error' }); statusEl && (statusEl.textContent = 'Erreur'); } if (json.note && statusEl) statusEl.title = json.note;
    // Rafraîchir les logs si l'onglet est visible pour voir immédiatement la ligne
    const logsSection = document.getElementById('section-logs');
    if (logsSection && logsSection.classList.contains('active')) {
        loadLogs();
    }
    const maintSection = document.getElementById('section-maintenance');
    if (maintSection && maintSection.classList.contains('active')) {
        loadMaintHistory();
    }
}
let __orphCursor = null; let __orphList = [];
async function maintScanOrphans() { const btn = $('scanOrphansBtn'); btn.disabled = true; const url = new URL('/api/admin/maint/scan-orphans', location.origin); if (__orphCursor) url.searchParams.set('cursor', __orphCursor); const { json: j } = await fetchJson(url.toString()); btn.disabled = false; if (j.orphans) { __orphCursor = j.truncated ? j.cursor : null; __orphList = __orphList.concat(j.orphans); renderOrphans(); $('deleteOrphansBtn').disabled = __orphList.length === 0; toast(`${j.orphans.length} orphelins trouvés (total ${__orphList.length})`, { type: 'success' }); } else { toast('Erreur scan', { type: 'error' }); } }
function renderOrphans() { const c = $('orphansList'); if (!c) return; if (!__orphList.length) { c.innerHTML = '<div class="muted">Aucun orphelin</div>'; return; } c.innerHTML = ''; const frag = document.createDocumentFragment(); __orphList.slice(-200).forEach(o => { const div = document.createElement('div'); div.className = 'orphan-row'; div.innerHTML = `<label><input type='checkbox' data-k='${o.key}' checked /> <span class='code'>${o.key}</span> <span class='muted'>${(o.size || 0)} bytes</span></label>`; frag.appendChild(div); }); c.appendChild(frag); }
async function maintDeleteOrphans() { if (!confirmAction('Supprimer les orphelins cochés ?')) return; const cbs = [...document.querySelectorAll('#orphansList input[type=checkbox]:checked')]; const keys = cbs.map(cb => cb.getAttribute('data-k')); if (!keys.length) { toast('Aucun élément sélectionné', { type: 'error' }); return; } const btn = $('deleteOrphansBtn'); btn.disabled = true; const { json: j } = await fetchJson('/api/admin/maint/delete-orphans', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ keys }) }); btn.disabled = false; if (j.ok) { __orphList = __orphList.filter(o => !keys.includes(o.key)); renderOrphans(); toast(`Supprimés: ${j.items || 0}`, { type: 'success' }); } else { toast('Erreur suppression', { type: 'error' }); } }

async function loadMaintHistory() {
    const wrap = $('maintHistory'); if (!wrap) return;
    const tbody = $('maintHistoryBody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="5">Chargement…</td></tr>';
    const { json: j } = await fetchJson('/api/admin/maint/history?limit=50');
    if (!j.runs || !j.runs.length) { if (tbody) tbody.innerHTML = '<tr><td colspan="5">Aucun historique</td></tr>'; return; }
    const fmt = ts => ts ? new Date(ts * 1000).toLocaleString() : '—';
    const runs = j.runs.slice(0, 50);
    const frag = document.createDocumentFragment();
    runs.forEach(run => {
        const tr = document.createElement('tr');
        const dur = (run.finished_at && run.started_at) ? (run.finished_at - run.started_at) + 's' : '—';
        let metaTooltip = '';
        if (run.meta) {
            try {
                const m = JSON.parse(run.meta);
                metaTooltip = JSON.stringify(m);
            } catch { metaTooltip = run.meta || ''; }
        }
        const badge = run.status ? `<span class='mh-badge ${run.status}'>${run.status}</span>` : '';
        tr.innerHTML = `<td title='${escapeHtml(metaTooltip)}'>${run.task}</td><td>${badge}</td><td>${run.items ?? '—'}</td><td>${run.started_at ? fmt(run.started_at) : '—'}</td><td>${dur}</td>`;
        frag.appendChild(tr);
    });
    if (tbody) { tbody.innerHTML = ''; tbody.appendChild(frag); }
    const lastCleanup = j.runs.find(r => r.task === 'cleanup' && r.status === 'ok');
    if (lastCleanup) { const statusVal = $('cleanupStatusValue'); statusVal && (statusVal.textContent = 'Dernier: ' + new Date(lastCleanup.finished_at * 1000).toLocaleString()); }
}

// --- Role policies ---
async function loadRolePolicies() {
    const { json } = await fetchJson('/api/admin/role-policies');
    const body = document.getElementById('rolePoliciesBody');
    if (!body) return;
    body.innerHTML = '';

    // Plus de labels en dur: fallback = role slug si label null
    (json.policies || []).forEach(p => {
        const tr = document.createElement('tr');
        const label = (p.label && p.label.trim()) || p.role;
        const coreRole = ['anon', 'admin', 'user'].includes(p.role); // non supprimable mais éditable
        tr.innerHTML = `<td><code>${p.role}</code></td>
        <td><input class="rp-input rp-label-input" data-rp="label" data-role="${p.role}" value="${label.replace(/"/g, '&quot;')}" style="width:140px" /></td>
        <td><input class="rp-input" data-rp="daily" data-role="${p.role}" value="${p.daily === null ? '-1' : (p.daily ?? '')}" placeholder="∞" /></td>
        <td><input class="rp-input" data-rp="cooldown" data-role="${p.role}" value="${p.cooldown_sec === null ? '-1' : (p.cooldown_sec ?? '')}" placeholder="—" /></td>
        <td><input class="rp-input" data-rp="autodel" data-role="${p.role}" value="${p.auto_delete_sec === null ? '-1' : (p.auto_delete_sec ?? '')}" placeholder="—" /></td>
        <td class="rp-actions"><div class="rp-actions-inner"><button class="btn btn-secondary btn-xs" data-rp-save="${p.role}">Sauver</button>${coreRole ? '' : `<button class="btn btn-error btn-xs" data-rp-del="${p.role}" title="Supprimer rôle">✕</button>`}</div></td>`;
        body.appendChild(tr);
    });
    body.querySelectorAll('[data-rp-save]').forEach(btn => {
        btn.addEventListener('click', async e => {
            const role = e.currentTarget.getAttribute('data-rp-save');
            const rowInputs = [...body.querySelectorAll(`[data-role="${role}"]`)];
            const map = {};
            rowInputs.forEach(inp => { const k = inp.getAttribute('data-rp'); map[k] = inp.value.trim(); });
            function toNullable(v) { if (v === '' || v === null || v === undefined) return null; if (v === '-1') return null; return v; }
            const payload = { role, label: map.label || null, daily: toNullable(map.daily), cooldown_sec: toNullable(map.cooldown), auto_delete_sec: toNullable(map.autodel) };
            const r = await fetch('/api/admin/role-policies', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
            if (r.ok) { toast('Rôle mis à jour', { type: 'success' }); loadRolePolicies(); } else { toast('Erreur update', { type: 'error' }); }
        });
    });
    // Création (toolbar au-dessus) - ne bind qu'une seule fois
    const createBtn = document.getElementById('createRoleBtn');
    if (createBtn && !createBtn.dataset.bound) {
        createBtn.dataset.bound = '1';
        createBtn.addEventListener('click', async () => {
            const name = (document.getElementById('newRoleName') || {}).value?.trim();
            const label = (document.getElementById('newRoleLabel') || {}).value?.trim();
            if (!name) { toast('Nom requis', { type: 'error' }); return; }
            const res = await fetch('/api/admin/role-policies', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ role: name, label }) });
            if (res.ok) { toast('Rôle créé', { type: 'success' }); (document.getElementById('newRoleName').value = ''); (document.getElementById('newRoleLabel').value = ''); loadRolePolicies(); }
            else { toast('Erreur création', { type: 'error' }); }
        });
    }
    // Suppression
    body.querySelectorAll('[data-rp-del]').forEach(btn => {
        btn.addEventListener('click', async e => {
            const role = e.currentTarget.getAttribute('data-rp-del');
            if (!role) return;
            if (!confirm('Supprimer le rôle ' + role + ' ? Les utilisateurs seront basculés sur user.')) return;
            const r = await fetch('/api/admin/role-policies/' + encodeURIComponent(role), { method: 'DELETE' });
            if (r.ok) { toast('Rôle supprimé', { type: 'success' }); loadRolePolicies(); } else { toast('Erreur suppression', { type: 'error' }); }
        });
    });
}

// --- DB Backups ---
async function loadDbBackups() {
    const listEl = $('dbBackupsList'); const lastEl = $('dbBackupLast');
    if (listEl) listEl.innerHTML = '<div class="muted">Chargement…</div>';
    const { json } = await fetchJson('/api/admin/maint/backups');
    const backups = (json && Array.isArray(json.backups)) ? json.backups : [];
    if (backups.length && lastEl) lastEl.textContent = new Date(backups[backups.length - 1].uploaded * 1000).toLocaleString();
    if (listEl) {
        if (!backups.length) { listEl.innerHTML = '<div class="muted">Aucun backup</div>'; return; }
        const frag = document.createDocumentFragment();
        backups.slice().reverse().forEach(b => {
            const div = document.createElement('div'); div.className = 'backup-row';
            const name = b.key.split('/').pop();
            div.innerHTML = `<span class='code'>${name}</span> <span class='muted'>${formatBytes(b.size)} • ${new Date(b.uploaded * 1000).toLocaleString()}</span>`;
            frag.appendChild(div);
        });
        listEl.innerHTML = ''; listEl.appendChild(frag);
    }
}

async function maintDbBackupNow() {
    const btn = $('dbBackupBtn'); if (btn) { btn.disabled = true; const o = btn.textContent; btn.textContent = 'En cours…'; }
    try {
        const { json } = await fetchJson('/api/admin/maint/db-backup', { method: 'POST' });
        if (json && json.ok) { toast('Backup terminé', { type: 'success' }); }
        else { toast('Échec backup', { type: 'error' }); }
    } catch { toast('Erreur réseau', { type: 'error' }); }
    finally { if (btn) { btn.disabled = false; btn.textContent = 'Sauvegarder maintenant'; } }
    loadDbBackups();
}