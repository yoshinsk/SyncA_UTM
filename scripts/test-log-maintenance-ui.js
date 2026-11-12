// scripts/test-log-maintenance-ui.js - ログ設定画面の保存・入力検査・異常表示を模擬APIで確認する。
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const html = fs.readFileSync('payload/server-gui/server_gui/templates/admin.html', 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const elements = new Map();
const element = id => {
    if (!elements.has(id)) elements.set(id, {value:'', textContent:'', valid:true, reportValidity(){return this.valid;}});
    return elements.get(id);
};
let data = {min_free_gb:25, free_bytes:12300000000, timer_active:true}, sent = [], notices = [];
const context = vm.createContext({
    document:{getElementById:element, addEventListener(){}}, window:{addEventListener(){}},
    bootstrap:{Modal:class {show(){} hide(){}}},
    api:{get:async url => url.includes('log-maintenance') ? data : {phase:'idle'},
        send:async (url, method, payload) => {sent.push({url, method, payload}); return {ok:true};}},
    setTimeout:()=>1, clearTimeout(){}, toast:(...args)=>notices.push(args), console,
});
const run = code => vm.runInContext(code, context);
(async () => {
    run(script);
    await run('loadLogMaintenance()');
    assert.equal(element('log-min-free-gb').value, 25);
    assert(element('log-maintenance-status').textContent.includes('12.30 GB'));
    element('log-min-free-gb').value = '30';
    await run('saveLogMaintenance()');
    assert.equal(sent.length, 1);
    assert.equal(sent[0].payload.min_free_gb, 30);
    assert.equal(sent[0].url, '/admin/api/log-maintenance');
    element('log-min-free-gb').valid = false;
    await run('saveLogMaintenance()');
    assert.equal(sent.length, 1);
    data = {...data, timer_active:false, last_result:{ran_at:'2026-11-12T03:15:00', ok:false, minimum_met:false, errors:['fixture']}};
    await run('loadLogMaintenance()');
    assert(element('log-maintenance-status').className.includes('text-danger'));
    assert(element('log-maintenance-status').textContent.includes('下回っています'));
    data = {error:'<script>fixture</script>'};
    await run('loadLogMaintenance()');
    assert.equal(element('log-maintenance-status').textContent, '<script>fixture</script>');
    assert.equal(element('log-maintenance-status').innerHTML, undefined);
    console.log('ログ保守UI: 設定読込・整数保存・入力検査・不足表示・エラーのテキスト表示 OK');
})().catch(error => {console.error(error); process.exitCode = 1;});
