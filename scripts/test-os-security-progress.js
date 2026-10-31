// scripts/test-os-security-progress.js: 実テンプレートの進捗表示と操作禁止を模擬APIで検証する。
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const html = fs.readFileSync('payload/server-gui/server_gui/templates/admin.html', 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const elements = new Map();
const el = id => { if (!elements.has(id)) elements.set(id, {disabled:false, value:'', checked:false, textContent:''}); return elements.get(id); };
let state = {phase:'idle', updated_at:1}, visible = false, sends = [], confirmations = [], resolveSend;
const context = vm.createContext({document:{getElementById:el, addEventListener(){}}, window:{addEventListener(){}},
    bootstrap:{Modal:class {show(){visible=true;} hide(){visible=false;}}},
    api:{get:async()=>state, send:async(url, method, payload)=>{sends.push(payload); return new Promise(r=>resolveSend=r);}},
    setTimeout:()=>1, clearTimeout(){}, toast(){}, confirm:text=>{confirmations.push(text); return true;}, console});
const run = code => vm.runInContext(code, context);
const flush = () => new Promise(resolve=>setImmediate(resolve));
const locked = () => ['os-plan','os-prepare','os-test','os-apply'].every(id=>el(id).disabled);
async function operation(action, phase, label, end) {
    const pending = run(`runOsSecurity('${action}')`);
    assert(visible); assert(locked()); assert.equal(el('os-progress-text').textContent,label);
    await run(`runOsSecurity('${action}')`); // 二重送信を抑止する。
    assert.equal(sends.filter(p=>p.action===action).length,1);
    resolveSend({ok:true}); await pending;
    assert(visible); assert(locked()); // worker開始前の古い状態では解除しない。
    state={...state,phase,job_active:true,updated_at:state.updated_at+1}; await run('loadOsSecurity()');
    assert(visible); assert(locked());
    state=null; await run('loadOsSecurity()'); assert(visible); assert(locked());
    state={...end,updated_at:20+sends.length,job_active:false}; await run('loadOsSecurity()');
    assert(!visible);
}
(async()=>{
    run(script); await flush();
    await operation('plan','planning','更新計画を確認中です',{phase:'planned',plan_id:'a',plan:{},message:'計画完了'});
    assert(!el('os-prepare').disabled); assert(el('os-test').disabled);
    assert(el('os-security-message').textContent.includes('2. 署名検証付きダウンロード'));
    await operation('prepare','preparing','署名検証付きダウンロード中です',{phase:'ready',plan_id:'a',plan:{transaction_test_ok:false}});
    assert(!el('os-test').disabled); assert(el('os-apply').disabled);
    await operation('test','testing','トランザクション検査中です',{phase:'ready',plan_id:'a',plan:{transaction_test_ok:true}});
    assert(!el('os-apply').disabled);
    el('os-maintenance').checked=true; el('os-recovery').checked=true; el('os-password').value='test-only';
    await operation('apply','applying','OS更新を適用中です',{phase:'reboot_scheduled',plan_id:'a',reboot_pending:true,message:'30秒後に再起動',last_apply:{phase:'reboot_scheduled',package_count:2}});
    assert(locked()); assert.equal(sends.at(-1).reboot_after_apply,true);
    assert(confirmations[0].includes('30秒')); assert.equal(el('os-password').value,'');
    assert(el('os-last-apply').textContent.includes('適用済み'));
    console.log('進捗ダイアログ・二重操作防止・次操作案内・再起動要求の検証 OK');
})().catch(error=>{console.error(error);process.exitCode=1;});
