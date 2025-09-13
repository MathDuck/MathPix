(function (global) {
    if (global.__utilsUnified) return;
    global.__utilsUnified = true;

    (function initTheme() {
        var root = document.documentElement;
        var storageKey = 'theme';
        var saved = null;
        try { saved = localStorage.getItem(storageKey); } catch (_) { }
        if (!saved) saved = 'dark';
        root.setAttribute('data-theme', saved);
        document.addEventListener('DOMContentLoaded', function () {
            var btn = document.getElementById('themeToggle');
            if (!btn) return;
            btn.addEventListener('click', function () {
                var current = root.getAttribute('data-theme') || 'dark';
                var next = current === 'dark' ? 'light' : 'dark';
                try { localStorage.setItem(storageKey, next); } catch (_) { }
                root.setAttribute('data-theme', next);
            });
        });
    })();

    function escapeHtml(value) {
        if (value === 0) return '0';
        if (!value) return '';
        return String(value).replace(/[&<>"']/g, function (ch) {
            return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[ch];
        });
    }
    if (!global.escapeHtml) global.escapeHtml = escapeHtml;

    function formatBytes(value) {
        if (value == null || isNaN(value)) return '—';
        if (typeof value !== 'number') {
            var n = Number(value); if (isNaN(n)) return '—'; value = n;
        }
        if (value < 1024) return value + ' B';
        var units = ['KB', 'MB', 'GB', 'TB'];
        var unitIndex = -1;
        do { value /= 1024; unitIndex++; } while (value >= 1024 && unitIndex < units.length - 1);
        return value.toFixed(1) + ' ' + units[unitIndex];
    }
    if (!global.formatBytes) global.formatBytes = formatBytes;
    if (!global.formatBytesProxy) global.formatBytesProxy = function (v) { return global.formatBytes ? global.formatBytes(v) : formatBytes(v); };

    (function () {
        var containerId = 'toastContainer';
        function ensureContainer() {
            var c = document.getElementById(containerId);
            if (!c) { c = document.createElement('div'); c.id = containerId; document.body.appendChild(c); }
            return c;
        }
        function animateIn(el) { requestAnimationFrame(function () { el.classList.add('show'); }); }
        function animateOut(el) { el.classList.remove('show'); setTimeout(function () { el.remove(); }, 300); }
        function toast(msg, opts) {
            opts = opts || {};
            var c = ensureContainer();
            var d = document.createElement('div');
            d.className = 'toast' + (opts.type === 'error' ? ' error' : (opts.type === 'success' ? ' success' : (opts.type === 'info' ? ' info' : '')));
            d.textContent = msg;
            c.appendChild(d);
            animateIn(d);
            var ttl = (typeof opts.ttl === 'number') ? opts.ttl : 6000;
            setTimeout(function () { animateOut(d); }, ttl);
        }
        function toastCountdown(seconds, opts) {
            opts = opts || {};
            seconds = Math.max(1, Math.ceil(seconds));
            var c = ensureContainer();
            var d = c.querySelector('.toast.cooldown');
            if (!d) { d = document.createElement('div'); d.className = 'toast cooldown error'; c.appendChild(d); animateIn(d); }
            var baseMsg = opts.message || 'Trop de tentatives. Réessayez dans {s}s';
            function render(s) { d.textContent = baseMsg.replace('{s}', String(s)); }
            render(seconds);
            if (d._cdInterval) clearInterval(d._cdInterval);
            d._cdInterval = setInterval(function () {
                seconds -= 1;
                if (seconds <= 0) { clearInterval(d._cdInterval); animateOut(d); }
                else render(seconds);
            }, 1000);
            return d;
        }
        if (!global.__toast) global.__toast = toast;
        if (!global.__toastCountdown) global.__toastCountdown = toastCountdown;
    })();

})(window);
