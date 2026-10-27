// Public, local-only Mihomo adapter. No site UI automation and no app launch.
'use strict';
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),net=require('node:net');
const {execFile}=require('node:child_process');

function validate(c){
 if(c.schema_version!==2||c.status!=='ready'||!['local_read','client_modify','reload','public_probe','browser_pause'].every(k=>c.authorization?.[k]===true))throw Error('authorization_record_required');
 if(!/^[A-Z]{2}$/.test(c.region)||c.detector_url!=='https://ippure.com/Browser-WebRTC-Leak-Detect')throw Error('invalid_scope');
 const r=c.routing,names=['group','fallback','probe_group','inbound','probe_inbound'].map(k=>r?.[k]);
 if(r.mode!=='global'||!names.every(n=>typeof n==='string'&&n.length>0&&n.length<=128&&!/[\x00-\x1f]/.test(n))||new Set(names).size!==5)throw Error('invalid_routes');
 if(!Array.isArray(r.nodes)||r.nodes.length<2||r.nodes.length>16||!r.nodes.every(n=>typeof n==='string'&&n.length>0&&n.length<=256&&!/[\x00-\x1f]/.test(n))||new Set(r.nodes).size!==r.nodes.length)throw Error('invalid_nodes');
 if([...names,...r.nodes].some(n=>['GLOBAL','DIRECT','REJECT','REJECT-DROP'].includes(n))||r.nodes.some(n=>names.includes(n)))throw Error('reserved_route');
 if(![r.port,r.probe_port].every(p=>Number.isInteger(p)&&p>=1024&&p<=65535)||r.port===r.probe_port)throw Error('invalid_ports');
 return c;
}
function destination(c){
 if(Boolean(c.controller)===Boolean(c.socket))throw Error('one_transport_required');
 if(c.socket){if(!(c.socket.startsWith('\\\\.\\pipe\\')||c.socket.startsWith('/')))throw Error('local_socket_required');return {socketPath:c.socket};}
 const url=new URL(c.controller);
 if(url.protocol!=='http:'||!['127.0.0.1','[::1]'].includes(url.hostname)||!url.port||url.username||url.password||url.pathname!=='/'||url.search||url.hash)throw Error('literal_loopback_required');
 return {hostname:url.hostname.replace(/[\[\]]/g,''),port:Number(url.port)};
}
function makeAPI(c){
 const dest=destination(c.controller);let token='';
 if(c.controller.token_file){if(fs.statSync(c.controller.token_file).size>8192)throw Error('invalid_token_file');token=fs.readFileSync(c.controller.token_file,'utf8').trim();if(/[\r\n]/.test(token))throw Error('invalid_token');}
 return (endpoint,method='GET',data)=>new Promise((resolve,reject)=>{
  if(!['GET','PUT','DELETE'].includes(method))return reject(Error('method_not_allowed'));
  const body=data===undefined?null:JSON.stringify(data);
  const req=http.request({...dest,path:endpoint,method,agent:false,headers:{...(token?{Authorization:'Bearer '+token}:{}),...(body?{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}:{})}},res=>{
   let count=0;const chunks=[];res.on('data',v=>{count+=v.length;if(count>16*1024*1024)req.destroy(Error('response_too_large'));else chunks.push(v)});
   res.on('error',()=>reject(Error('response_failed')));
   res.on('end',()=>{if(res.statusCode<200||res.statusCode>=300)return reject(Error('local_api_failed'));try{const text=Buffer.concat(chunks).toString('utf8');resolve(text?JSON.parse(text):null)}catch{reject(Error('invalid_local_json'))}});
  });
  const timer=setTimeout(()=>req.destroy(Error('local_api_deadline')),5000);req.on('close',()=>clearTimeout(timer));req.on('error',()=>reject(Error('local_api_unavailable')));req.end(body);
 });
}
function trace(port){
 return new Promise(resolve=>execFile('curl.exe',['-sS','--noproxy','','--connect-timeout','4','--max-time','8','--proto','=https','--proxy',`http://127.0.0.1:${port}`,'https://www.cloudflare.com/cdn-cgi/trace'],{windowsHide:true,timeout:10000,maxBuffer:65536},(error,out)=>{
  const ip=out?.match(/^ip=(.+)$/m)?.[1]?.trim(),country=out?.match(/^loc=(.+)$/m)?.[1]?.trim();resolve({success:!error&&Boolean(net.isIP(ip||'')),ip,country});
 }));
}
function atomic(file,data){const tmp=file+'.tmp-'+process.pid;fs.writeFileSync(tmp,JSON.stringify(data));try{fs.renameSync(tmp,file)}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp)}}
function makeAdapter(config,{api,probe=trace,directory,now=()=>Date.now()/1000}={}){
 const c=validate(config),r=c.routing;api=api||makeAPI(c);
 const choose=(group,name)=>api('/proxies/'+encodeURIComponent(group),'PUT',{name});
 const journalFile=path.join(directory,'route-journal.json');
 const state=()=>JSON.parse(fs.readFileSync(path.join(directory,'state.json'),'utf8'));
 async function layout(){
  const cfg=await api('/configs'),ps=(await api('/proxies')).proxies;
  if(cfg.mode!=='global')throw Error('mode_changed');
  const equal=(a,b)=>Array.isArray(a)&&a.length===b.length&&new Set(a).size===a.length&&b.every(n=>a.includes(n));
  if(ps[r.group]?.type!=='Selector'||!equal(ps[r.group].all,[r.fallback,...r.nodes,'REJECT'])||ps[r.probe_group]?.type!=='Selector'||!equal(ps[r.probe_group].all,r.nodes)||ps[r.fallback]?.type!=='Fallback'||!equal(ps[r.fallback].all,r.nodes))throw Error('route_shape_changed');
  if(r.nodes.some(n=>!ps[n]||ps[n].all||['Direct','Reject','RejectDrop'].includes(ps[n].type)))throw Error('physical_nodes_required');
  return ps;
 }
 async function closeEntry(){for(const con of (await api('/connections')).connections||[])if(con.metadata?.inboundName===r.inbound)await api('/connections/'+encodeURIComponent(con.id),'DELETE');}
 return async(action,data={})=>{
  // Recovery deployment reload is separate; never silently repair unexpected layout.
  if(action==='reload'){
   if(!['candidate.yaml','original.yaml'].includes(data.file))throw Error('bundle_file_required');
   await api('/configs?force=true','PUT',{payload:fs.readFileSync(path.join(directory,data.file),'utf8')});return {reloaded:true};
  }
  if(action==='snapshot'){const cfg=await api('/configs'),ps=(await api('/proxies')).proxies;return {mode:cfg.mode,selectors:Object.fromEntries(Object.entries(ps).filter(([,v])=>v.type==='Selector').map(([n,v])=>[n,v.now]))};}
  if(action==='restore-selectors'){
   const saved=JSON.parse(fs.readFileSync(path.join(directory,'selectors.json'),'utf8'));
   for(const [name,value] of Object.entries(saved.selectors||{}))await choose(name,value);return {restored:true};
  }
  const ps=await layout();
  if(action==='inspect')return {verified:true,mode:'global',selected_default:ps[r.group].now===r.fallback,blocked:ps[r.group].now==='REJECT'};
  if(action==='check'||action==='check-live'){
   const rows=(await api('/connections')).connections||[];
   const live=rows.some(v=>v.metadata?.host==='ippure.com'&&v.metadata?.inboundName===r.inbound&&v.chains?.includes(r.group)&&!v.chains.includes('GLOBAL'));
   const routeSignature=JSON.stringify([ps[r.group].now,ps[r.fallback].now]);let recent=false;
   if(action==='check'&&c.evidence_mode==='native-browser')try{
    const receipt=JSON.parse(fs.readFileSync(path.join(directory,'native-channel.json'),'utf8')),age=now()-receipt.observed_at;
    recent=receipt.verified===true&&receipt.scope_id===c.browser.scope_id&&receipt.routeSignature===routeSignature&&age>=0&&age<=90;
   }catch{}
   return {verified:live||recent,routeSignature};
  }
  if(action==='block'){atomic(journalFile,{phase:'cancelled',at:now()});await choose(r.group,'REJECT');await closeEntry();return {blocked:(await layout())[r.group].now==='REJECT'};}
  if(action==='enable'){await choose(r.group,r.fallback);atomic(journalFile,{phase:'armed',at:now()});return {enabled:(await layout())[r.group].now===r.fallback};}
  if(action!=='switch'||!net.isIP(data.previous_exit||''))throw Error('invalid_action');
  const s=state();if(s.phase!=='switch_required'||s.switch_count!==1)throw Error('switch_intent_required');
  if(fs.existsSync(journalFile)&&JSON.parse(fs.readFileSync(journalFile)).phase!=='armed')throw Error('switch_not_replayable');
  const intent={phase:'preparing',detected_at:s.detected_at,at:now()};atomic(journalFile,intent);
  const initialGlobal=ps.GLOBAL?.now,oldProbe=ps[r.probe_group].now;let chosen;
  try{
   for(const node of r.nodes){await choose(r.probe_group,node);const p=await probe(r.probe_port);if(p.success&&p.country===c.region&&net.isIP(p.ip||'')&&p.ip!==data.previous_exit){chosen={node,...p};break;}}
  }finally{await choose(r.probe_group,oldProbe);}
  if(!chosen)return {kind:'switch_receipt',success:false,observed_at:now()};
  const current=state(),journal=JSON.parse(fs.readFileSync(journalFile));
  if(current.phase!=='switch_required'||current.detected_at!==s.detected_at||journal.phase!=='preparing')throw Error('switch_cancelled');
  atomic(journalFile,{...intent,phase:'commit_pending'});
  await choose(r.group,chosen.node);await closeEntry();
  const after=await probe(r.port),final=await layout();
  const receipt={kind:'switch_receipt',success:after.success&&after.ip===chosen.ip&&after.country===c.region&&final.GLOBAL?.now===initialGlobal&&final[r.group].now===chosen.node,
    node:chosen.node,country:after.country,exit_ip:after.ip,observed_at:now()};
  atomic(journalFile,{phase:'committed',at:now(),receipt});return receipt;
 };
}
module.exports={validate,destination,makeAPI,makeAdapter};
if(require.main===module){
 let input='';process.stdin.on('data',v=>{input+=v;if(input.length>65536)process.exit(2)});
 process.stdin.on('end',async()=>{try{const file=path.resolve(process.argv[2]),config=JSON.parse(fs.readFileSync(file,'utf8'));const run=makeAdapter(config,{directory:path.dirname(file)});console.log(JSON.stringify(await run(process.argv[3],input?JSON.parse(input):{})))}catch{console.error('Mihomo guard adapter failed; inspect private state without replaying a switch.');process.exitCode=1}});
}
