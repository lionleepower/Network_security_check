'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http');
const {makeAdapter,makeAPI,destination}=require('./mihomo_guard_adapter.cjs');
function fixture(t){
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'public-guard-'));t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 const c={schema_version:2,status:'ready',authorization:Object.fromEntries(['local_read','client_modify','reload','public_probe','browser_pause'].map(k=>[k,true])),region:'JP',detector_url:'https://ippure.com/Browser-WebRTC-Leak-Detect',routing:{mode:'global',group:'Guard',fallback:'Fallback',probe_group:'Probe',inbound:'private',probe_inbound:'probe',port:29181,probe_port:29182,nodes:['A','B']}};
 const ps={GLOBAL:{type:'Selector',now:'Other',all:['Other']},Guard:{type:'Selector',now:'Fallback',all:['Fallback','A','B','REJECT']},Fallback:{type:'Fallback',now:'A',all:['A','B']},Probe:{type:'Selector',now:'A',all:['A','B']},A:{type:'Shadowsocks'},B:{type:'Shadowsocks'}};
 const calls=[],connections=[{id:'own',metadata:{host:'ippure.com',inboundName:'private'},chains:['Guard','A']},{id:'other',metadata:{host:'example.org',inboundName:'mixed'},chains:['GLOBAL']}];
 const api=async(url,method='GET',body)=>{
  calls.push({url,method,body});
  if(url==='/configs')return {mode:'global'};
  if(url==='/proxies')return {proxies:ps};
  if(url==='/connections')return {connections};
  if(method==='PUT'&&url.startsWith('/proxies/')){ps[decodeURIComponent(url.slice(9))].now=body.name;return null;}
  if(method==='DELETE'&&url.startsWith('/connections/'))return null;
  throw Error('unexpected endpoint');
 };
 const writeState=()=>fs.writeFileSync(path.join(directory,'state.json'),JSON.stringify({phase:'switch_required',switch_count:1,detected_at:100}));
 writeState();
 const probe=async port=>{const node=port===29182?ps.Probe.now:ps.Guard.now;return {success:true,country:'JP',ip:node==='B'?'203.0.113.2':'203.0.113.1'}};
 return {c,directory,ps,calls,api,probe,writeState,run:makeAdapter(c,{api,probe,directory})};
}
test('fresh different JP exit, one production switch and no GLOBAL mutation',async t=>{
 const f=fixture(t);await f.run('enable');const result=await f.run('switch',{previous_exit:'203.0.113.1'});
 assert.equal(result.success,true);assert.equal(result.country,'JP');assert.equal(result.exit_ip,'203.0.113.2');
 assert.equal(f.ps.GLOBAL.now,'Other');assert.equal(f.ps.Probe.now,'A');
 assert.deepEqual(f.calls.filter(v=>v.method==='DELETE').map(v=>v.url),['/connections/own']);
 await assert.rejects(()=>f.run('switch',{previous_exit:'203.0.113.1'}));
 assert.equal(f.calls.filter(v=>v.url==='/proxies/Guard'&&v.body?.name==='B').length,1);
});
test('same exit and wrong country never switch production',async t=>{
 const f=fixture(t);
 for(const country of ['JP','US']){
  const probe=async()=>({success:true,country,ip:'203.0.113.1'});
  const run=makeAdapter(f.c,{api:f.api,probe,directory:f.directory});await run('enable');
  assert.equal((await run('switch',{previous_exit:'203.0.113.1'})).success,false);
 }
 assert.equal(f.ps.Guard.now,'Fallback');
});
test('cancel during probe prevents late production mutation',async t=>{
 const f=fixture(t);const probe=async()=>{fs.writeFileSync(path.join(f.directory,'state.json'),JSON.stringify({phase:'suspend_required'}));return {success:true,country:'JP',ip:'203.0.113.2'}};
 const run=makeAdapter(f.c,{api:f.api,probe,directory:f.directory});await run('enable');
 await assert.rejects(()=>run('switch',{previous_exit:'203.0.113.1'}));assert.equal(f.ps.Guard.now,'Fallback');
});
test('probe failure restores only probe selection; interrupted commit is not replayed',async t=>{
 const f=fixture(t);const run=makeAdapter(f.c,{api:f.api,probe:async()=>{throw Error('offline')},directory:f.directory});await run('enable');
 await assert.rejects(()=>run('switch',{previous_exit:'203.0.113.1'}));assert.equal(f.ps.Probe.now,'A');
 await assert.rejects(()=>run('switch',{previous_exit:'203.0.113.1'}));
});
test('block scopes socket deletion and rejection to dedicated entry',async t=>{
 const f=fixture(t);assert.equal((await f.run('block')).blocked,true);assert.equal(f.ps.GLOBAL.now,'Other');
 assert.deepEqual(f.calls.filter(v=>v.method==='DELETE').map(v=>v.url),['/connections/own']);
});
test('channel and shape mismatch rejected',async t=>{
 const f=fixture(t);assert.equal((await f.run('check')).verified,true);
 f.ps.Fallback.all.push('DIRECT');await assert.rejects(()=>f.run('check'));
});
test('native receipt is scoped, fresh, route-bound and never replaces check-live',async t=>{
 const f=fixture(t);f.c.evidence_mode='native-browser';f.c.browser={scope_id:'fixture-scope'};
 const live=await f.run('check-live');assert.equal(live.verified,true);
 const filename=path.join(f.directory,'native-channel.json');
 const receipt={verified:true,scope_id:'fixture-scope',observed_at:Date.now()/1000,routeSignature:live.routeSignature};
 const api=async(endpoint,...args)=>endpoint==='/connections'?{connections:[]}:f.api(endpoint,...args);
 const run=makeAdapter(f.c,{api,probe:f.probe,directory:f.directory});
 fs.writeFileSync(filename,JSON.stringify(receipt));assert.equal((await run('check')).verified,true);assert.equal((await run('check-live')).verified,false);
 for(const changed of [{scope_id:'other'},{observed_at:Date.now()/1000-91},{routeSignature:'changed'}]){
  fs.writeFileSync(filename,JSON.stringify({...receipt,...changed}));assert.equal((await run('check')).verified,false);
 }
});
test('remote controller and embedded credentials rejected',()=>{
 for(const controller of ['http://example.org:9090/','http://'+'u:p@127.0.0.1:9090/','https://127.0.0.1:9090/'])assert.throws(()=>destination({controller}));
 assert.deepEqual(destination({controller:'http://127.0.0.1:9090/'}),{hostname:'127.0.0.1',port:9090});
});
test('actual loopback HTTP transport handles chunked UTF-8 and private authorization',async t=>{
 const server=http.createServer((req,res)=>{assert.equal(req.headers.authorization,'Bearer fixture-token');res.writeHead(200,{'Content-Type':'application/json'});const bytes=Buffer.from(JSON.stringify({value:'测试'}));res.write(bytes.subarray(0,11));res.end(bytes.subarray(11));});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'guard-token-'));t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 const file=path.join(directory,'token');fs.writeFileSync(file,'fixture-token');
 const api=makeAPI({controller:{controller:`http://127.0.0.1:${server.address().port}/`,token_file:file}});
 assert.deepEqual(await api('/version'),{value:'测试'});
});
