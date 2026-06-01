/* payload/server-gui/server_gui/static/app.js
   Shared frontend helpers for SyncA UTM's Bootstrap based server GUI. */
'use strict';

const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
const loadingText = '読み込み中...';
const processingText = '処理中...';

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

const SyncAUI = (() => {
    const buttonSelector = [
        'button',
        'input[type="button"]',
        'input[type="submit"]',
        'input[type="reset"]',
        'a.btn',
    ].join(',');
    let activeRequests = 0;
    let loadingTimer = null;
    let loadingEl = null;

    function ensureLoadingEl() {
        if (loadingEl) return loadingEl;
        loadingEl = document.createElement('div');
        loadingEl.id = 'synca-loading-indicator';
        loadingEl.className = 'synca-loading-indicator shadow-sm';
        loadingEl.setAttribute('role', 'status');
        loadingEl.setAttribute('aria-live', 'polite');
        loadingEl.innerHTML = `
            <span class="spinner-border spinner-border-sm" aria-hidden="true"></span>
            <span class="synca-loading-text">${loadingText}</span>`;
        document.body.appendChild(loadingEl);
        return loadingEl;
    }

    function setButtonsDisabled(disabled) {
        for (const button of document.querySelectorAll(buttonSelector)) {
            if (button.dataset.syncaAllowBusy === 'true') continue;
            const isLinkButton = button.matches('a.btn');
            if (disabled) {
                if (isLinkButton && !button.classList.contains('disabled')) {
                    button.dataset.syncaBusyDisabled = '1';
                    button.dataset.syncaPreviousTabindex = button.getAttribute('tabindex') || '';
                    button.classList.add('disabled');
                    button.setAttribute('aria-disabled', 'true');
                    button.setAttribute('tabindex', '-1');
                } else if (!isLinkButton && !button.disabled) {
                    button.dataset.syncaBusyDisabled = '1';
                    button.disabled = true;
                    button.setAttribute('aria-disabled', 'true');
                }
            } else if (button.dataset.syncaBusyDisabled === '1') {
                if (isLinkButton) {
                    button.classList.remove('disabled');
                    if (button.dataset.syncaPreviousTabindex) {
                        button.setAttribute('tabindex', button.dataset.syncaPreviousTabindex);
                    } else {
                        button.removeAttribute('tabindex');
                    }
                    delete button.dataset.syncaPreviousTabindex;
                } else {
                    button.disabled = false;
                }
                button.removeAttribute('aria-disabled');
                delete button.dataset.syncaBusyDisabled;
            }
        }
    }

    function showLoading(message) {
        const el = ensureLoadingEl();
        el.querySelector('.synca-loading-text').textContent = message || loadingText;
        clearTimeout(loadingTimer);
        loadingTimer = setTimeout(() => {
            if (activeRequests > 0) el.classList.add('show');
        }, 250);
    }

    function hideLoading() {
        clearTimeout(loadingTimer);
        loadingTimer = null;
        if (loadingEl) loadingEl.classList.remove('show');
        document.body.classList.remove('synca-ui-busy');
        document.body.removeAttribute('aria-busy');
    }

    function begin(options = {}) {
        activeRequests += 1;
        document.body.classList.add('synca-ui-busy');
        document.body.setAttribute('aria-busy', 'true');
        setButtonsDisabled(true);
        showLoading(options.message || loadingText);
        return { ended: false };
    }

    function end(token) {
        if (!token || token.ended) return;
        token.ended = true;
        activeRequests = Math.max(0, activeRequests - 1);
        if (activeRequests === 0) {
            setButtonsDisabled(false);
            hideLoading();
        }
    }

    async function track(fn, options = {}) {
        const token = begin(options);
        try {
            return await fn();
        } finally {
            end(token);
        }
    }

    async function fetchWithUi(input, init = {}) {
        const method = String(init.method || 'GET').toUpperCase();
        const message = method === 'GET' ? loadingText : processingText;
        return track(() => window.fetch(input, init), { message });
    }

    return {
        begin,
        end,
        fetch: fetchWithUi,
        isBusy: () => activeRequests > 0,
        track,
    };
})();
window.SyncAUI = SyncAUI;

document.addEventListener('click', (event) => {
    if (!SyncAUI.isBusy()) return;
    const target = event.target instanceof Element
        ? event.target.closest('button,input[type="button"],input[type="submit"],input[type="reset"],a.btn')
        : null;
    if (!target || target.dataset.syncaAllowBusy === 'true') return;
    event.preventDefault();
    event.stopImmediatePropagation();
}, true);

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
        const uiToken = SyncAUI.begin({ message: loadingText });
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
        } finally {
            SyncAUI.end(uiToken);
        }
    },
    async send(url, method, payload) {
        const ctx = { method, url };
        const t0 = performance.now();
        const uiToken = SyncAUI.begin({ message: processingText });
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
        } finally {
            SyncAUI.end(uiToken);
        }
    },
};
