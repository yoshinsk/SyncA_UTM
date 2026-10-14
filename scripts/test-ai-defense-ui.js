/* scripts/test-ai-defense-ui.js
   Verify that a failed manual AI-defense request refreshes the saved result
   and releases the action button, without a browser or appliance access. */
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const template = fs.readFileSync(path.join(__dirname, '..', 'payload', 'server-gui', 'server_gui', 'templates', 'ai_defense.html'), 'utf8');
const script = template.match(/<script>([\s\S]*?)<\/script>/)[1];

async function verifyManualCheck(send) {
    const elements = new Map();
    const toasts = [];
    let reads = 0;
    const message = 'Jev API が判定要求の形式を受け付けませんでした。';
    const context = vm.createContext({
        document: {
            getElementById(id) {
                if (!elements.has(id)) elements.set(id, { disabled: false, value: '', innerHTML: '', textContent: '' });
                return elements.get(id);
            },
        },
        api: {
            send,
            async get() {
                reads += 1;
                return { enabled: true, api_key_configured: true, interval_hours: 8,
                    last_result: { message }, blocked: [] };
            },
        },
        confirm: () => true,
        toast: (...args) => toasts.push(args),
        escapeHtml: value => String(value),
    });
    // The page performs an initial status read. Run the real template script
    // rather than duplicating its checkNow implementation in this fixture.
    await vm.runInContext(script, context);
    const initialReads = reads;
    try {
        await context.checkNow();
    } catch (error) {
        assert.equal(error.message, 'transport failure');
    }
    assert.equal(reads, initialReads + 1, 'a manual check must reload the persisted result');
    assert.equal(elements.get('last-result').textContent, message);
    assert.equal(elements.get('check-now-button').disabled, false);
    return toasts;
}

async function main() {
    // Shared API helpers return null after showing an HTTP-error toast. The
    // page must still update its "previous result" instead of leaving it stale.
    assert.equal((await verifyManualCheck(async () => null)).length, 0);
    await verifyManualCheck(async () => { throw new Error('transport failure'); });
    assert.equal((await verifyManualCheck(async () => ({ ok: true, message: '確認を完了しました。' }))).length, 1);
    console.log('AI-defense UI: HTTP error, transport failure, and success checks passed.');
}

main().catch(error => { console.error(error); process.exitCode = 1; });
