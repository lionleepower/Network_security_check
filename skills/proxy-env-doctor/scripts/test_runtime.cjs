'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const {summarize, validatePlan, transport, makeGet, collect} = require('./collect_runtime.cjs');
const plan = {schema_version:1,status:'ready',mode:'global',authorization:{local_read:true},test_targets:['api.anthropic.com'],
  claude:{group:'private-group',listener:'private-inbound',allow_failover:false,failure_action:'reject',session_policy:'do-not-touch-existing',web_test_context:'private-or-isolated'}};
const raw = () => ({configs:{mode:'global',tun:{enable:true,'dns-hijack':['any:53','tcp://any:53']}},proxies:{proxies:{'private-group':{type:'Selector',all:['secret-node'],now:'secret-node'},'secret-node':{type:'Shadowsocks'},DIRECT:{type:'Direct'}}},
  connections:{connections:[{id:'secret-id',start:new Date().toISOString(),metadata:{host:'api.anthropic.com',network:'tcp',type:'HTTP',inboundName:'private-inbound',sourceIP:'PRIVATE-IP',processPath:'PRIVATE-PROCESS'},chains:['secret-node','private-group']},
  {metadata:{host:'private-browsing.example',network:'tcp'},chains:['secret-node']}]}});

test('redacts names, addresses, processes, connection IDs and unrelated browsing',()=>{
  const result=summarize(raw(),plan,'2026-01-01T00:00:00Z');const encoded=JSON.stringify(result);
  for(const value of ['private-group','private-inbound','secret-node','secret-id','PRIVATE-IP','PRIVATE-PROCESS','private-browsing.example'])assert.equal(encoded.includes(value),false);
  assert.equal(result.connections.length,1);assert.equal(result.connections[0].expected_inbound,true);
  assert.equal(result.connections[0].lifetime,'started_after_capture');
});
test('does not upgrade old or timestamp-less connections to new evidence',()=>{
  const data=raw();data.connections.connections[0].start='2020-01-01T00:00:00Z';
  assert.equal(summarize(data,plan,'2026-01-01T00:00:00Z').connections[0].lifetime,'preexisting');
  delete data.connections.connections[0].start;
  assert.equal(summarize(data,plan,'2026-01-01T00:00:00Z').connections[0].lifetime,'start_unknown');
  data.connections.connections[0].start='2999-01-01T00:00:00Z';
  assert.equal(summarize(data,plan,'2026-01-01T00:00:00Z').connections[0].lifetime,'start_unknown');
});
test('requires literal loopback, no credentials, no remote sockets',()=>{
  for(const controller of ['http://example.com','http://localhost','https://127.0.0.1','http://'+'user:secret@127.0.0.1','http://127.0.0.1/configs'])assert.throws(()=>transport({controller}));
  assert.throws(()=>transport({socket:'\\\\remote\\pipe\\core'}));
  assert.equal(transport({controller:'http://127.0.0.1:9090'}).hostname,'127.0.0.1');
  assert.equal(transport({controller:'http://[::1]:9090'}).hostname,'::1');
});
test('refuses live access without recorded permission and preserves session restriction',()=>{
  assert.throws(()=>validatePlan({...plan,authorization:{}},true));
  assert.throws(()=>validatePlan({...plan,claude:{...plan.claude,session_policy:'reuse-login'}},true));
  assert.throws(()=>validatePlan({...plan,test_targets:['https://api.anthropic.com/key=secret']},true));
});
test('only GETs allowed API endpoints, handles chunked JSON and ignores redirects',async()=>{
  const requested=[];const data=raw();const server=http.createServer((req,res)=>{
    requested.push([req.method,req.url]);
    if(req.url==='/version'){res.writeHead(200,{'Content-Type':'application/json'});res.write('{"meta":');res.end('true}');return;}
    const value={'/configs':data.configs,'/proxies':data.proxies,'/connections':data.connections}[req.url];
    res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(value));
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try{const options={controller:'http://127.0.0.1:'+server.address().port,duration:'0'};
    const result=await collect(options,plan);assert.equal(result.source,'local-api');assert.equal(result.state_changed_during_capture,false);
    await assert.rejects(makeGet(options)('/restart'));
    assert.ok(requested.every(([method])=>method==='GET'));assert.ok(requested.some(([,url])=>url==='/connections'));
  }finally{await new Promise(r=>server.close(r));}
});
test('detects configuration changes during capture',async()=>{
  let configCalls=0;const data=raw();const server=http.createServer((req,res)=>{
    const cfg={mode:++configCalls>2?'rule':'global'};
    const value={'/version':{},'/configs':cfg,'/proxies':data.proxies,'/connections':data.connections}[req.url];res.end(JSON.stringify(value));
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try{const result=await collect({controller:'http://127.0.0.1:'+server.address().port,duration:'0'},plan);assert.equal(result.state_changed_during_capture,true);}
  finally{await new Promise(r=>server.close(r));}
});
test('forbidden redirects are not followed',async()=>{
  const server=http.createServer((req,res)=>{res.writeHead(302,{Location:'http://example.com/private'});res.end();});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try{await assert.rejects(makeGet({controller:'http://127.0.0.1:'+server.address().port})('/version'),/302/);}
  finally{await new Promise(r=>server.close(r));}
});
