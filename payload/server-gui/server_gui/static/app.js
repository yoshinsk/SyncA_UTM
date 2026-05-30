/* Shared helpers for the server-gui frontend. Bootstrap 5 based. */
'use strict';

const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

/* Pageunload detection: suppress noisy toasts that fire when in-flight fetches
   are aborted by navigation. Errors still go to the browser console. */
let _pageUnloading = false;
window.addEventListener('beforeunload', () => { _pageUnloading = true; });
window.addEventListener('pagehide',     () => { _pageUnloading = true; });

/* Surface uncaught client-side errors to the console — F12 → Console to inspect.
   Backend errors are logged to journald (journalctl -u server-gui.service). */
window.addEventListener('error', (e) => {
    console.error('[uncaught]', e.message, e.filename + ':' + e.lineno, e.error);
});
window.addEventListener('unhandledrejection', (e) => {
    console.error('[unhandled-rejection]', e.reason);
});

function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function toast(message, isError = false) {
    const container = document.getElementById('toast-container');
    if (!container || typeof bootstrap === 'undefined') {
        console[isError ? 'error' : 'log']('[toast]', message);
        return;
    }
    const el = document.createElement('div');
    el.className = `toast align-items-center text-white border-0 ${isError ? 'bg-danger' : 'bg-success'}`;
    el.setAttribute('role', 'alert');
    el.setAttribute('aria-live', 'assertive');
    el.setAttribute('aria-atomic', 'true');
    const icon = isError ? 'bi-exclamation-triangle-fill' : 'bi-check-circle-fill';
    el.innerHTML = `
        <div class="d-flex">
            <div class="toast-body d-flex align-items-center gap-2">
                <i class="bi ${icon}"></i>
                <span></span>
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>`;
    el.querySelector('.toast-body span').textContent = message;
    container.appendChild(el);
    const instance = new bootstrap.Toast(el, { delay: isError ? 6000 : 3500 });
    instance.show();
    el.addEventListener('hidden.bs.toast', () => el.remove());
}

const api = {
    async _handle(res, ctx) {
        if (res.status === 401) {
            console.warn('[api]', ctx.method, ctx.url, '→ 401, redirecting to /login');
            window.location.href = '/login';
            return null;
        }
        let body = null;
        try { body = await res.json(); } catch (_) {}
        if (!res.ok) {
            console.error('[api]', ctx.method, ctx.url, '→', res.status, body);
            toast((body && body.error) || `HTTP ${res.status}`, true);
            return null;
        }
        return body;
    },
    async get(url) {
        const ctx = { method: 'GET', url };
        const t0 = performance.now();
        try {
            const res = await fetch(url, { credentials: 'same-origin' });
            const out = await this._handle(res, ctx);
            console.debug('[api] GET', url, `${Math.round(performance.now() - t0)}ms`, '→', res.status);
            return out;
        } catch (e) {
            if (_pageUnloading) {
                console.debug('[api] GET', url, 'aborted by navigation');
                return null;
            }
            console.error('[api] GET', url, 'failed:', e);
            toast('通信エラー: ' + e.message, true);
            return null;
        }
    },
    async send(url, method, payload) {
        const ctx = { method, url };
        const t0 = performance.now();
        try {
            const res = await fetch(url, {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken,
                },
                credentials: 'same-origin',
                body: payload !== undefined ? JSON.stringify(payload) : null,
            });
            const out = await this._handle(res, ctx);
            console.debug('[api]', method, url, `${Math.round(performance.now() - t0)}ms`, '→', res.status);
            return out;
        } catch (e) {
            if (_pageUnloading) {
                console.debug('[api]', method, url, 'aborted by navigation');
                return null;
            }
            console.error('[api]', method, url, 'failed:', e);
            toast('通信エラー: ' + e.message, true);
            return null;
        }
    },
};
