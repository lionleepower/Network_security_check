'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {localURL,checkRoute}=require('./native_ippure_collector.cjs');
test('debug endpoints only accept literal local addresses without credentials',()=>{
 for(const url of ['ws://example.org:9222/','ws://localhost:9222/','ws://u:p@127.0.0.1:9222/','http://127.0.0.1:9222/'])assert.throws(()=>localURL(url,'ws:'));
 assert.equal(localURL('ws://127.0.0.1:12345/devtools/browser/test','ws:').port,'12345');
});
test('route helper stdin is closed so a real subprocess can finish',async()=>{
 const command=[process.execPath,'-e',"let s='';process.stdin.on('data',v=>s+=v);process.stdin.on('end',()=>console.log(JSON.stringify({verified:s==='{}'})));",'--'];
 const result=await checkRoute(command);assert.equal(result.verified,true);
});
test('failed or non-JSON helper never counts as verified',async()=>{
 const result=await checkRoute([process.execPath,'-e',"process.stdout.write('not-json')",'--']);assert.equal(result.verified,false);
});
