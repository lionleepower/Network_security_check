// User-requested standalone automation. Own empty Edge profile only, no accounts.
'use strict';
const fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const {spawn,execFile}=require('node:child_process');
const URL_FIXED='https://ippure.com/Browser-WebRTC-Leak-Detect';
const delay=ms=>new Promise(r=>setTimeout(r,ms));
function localURL(value,protocol){const u=new URL(value);if(u.protocol!==protocol||!['127.0.0.1','[::1]'].includes(u.hostname)||!u.port||u.username||u.password)throw Error('nonlocal_debug_endpoint');return u;}
function getJSON(url){localURL(url,'http:');return new Promise((resolve,reject)=>{
 const req=http.get(url,{agent:false},res=>{let data='';res.on('data',c=>{data+=c;if(data.length>1024*1024)req.destroy()});res.on('end',()=>{try{if(res.statusCode!==200)throw Error();resolve(JSON.parse(data))}catch{reject(Error('debug_metadata_invalid'))}})});
 req.setTimeout(2000,()=>req.destroy());req.on('error',()=>reject(Error('debug_endpoint_unavailable')));
});}
class CDP{
 constructor(socket){this.socket=socket;this.id=0;this.pending=new Map();socket.addEventListener('message',event=>{let d;try{d=JSON.parse(event.data)}catch{return;}const p=this.pending.get(d.id);if(p){this.pending.delete(d.id);clearTimeout(p.timer);d.error?p.reject(Error('browser_command_failed')):p.resolve(d.result)}});socket.addEventListener('close',()=>{for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(Error('browser_disconnected'))}this.pending.clear()});}
 static async connect(url){localURL(url,'ws:');const s=new WebSocket(url);await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{s.close();reject(Error('debug_connect_timeout'))},5000);s.addEventListener('open',()=>{clearTimeout(timer);resolve()},{once:true});s.addEventListener('error',()=>{clearTimeout(timer);reject(Error('debug_connect_failed'))},{once:true})});return new CDP(s);}
 call(method,params={}){return new Promise((resolve,reject)=>{const id=++this.id;const timer=setTimeout(()=>{this.pending.delete(id);reject(Error('browser_command_timeout'))},8000);this.pending.set(id,{resolve,reject,timer});this.socket.send(JSON.stringify({id,method,params}));});}
 close(){this.socket.close();}
}
function checkRoute(command){return new Promise(resolve=>{const child=execFile(command[0],[...command.slice(1),'check-live'],{windowsHide:true,timeout:5000,maxBuffer:65536},(error,out)=>{try{resolve(error?{verified:false}:JSON.parse(out))}catch{resolve({verified:false})}});child.stdin.end('{}');});}
function atomic(file,value){const temp=file+'.tmp-'+process.pid;fs.writeFileSync(temp,JSON.stringify(value));fs.renameSync(temp,file);}
const READ_DOM=`(()=>{const rows=Array.from(document.querySelectorAll('table tr')).map(r=>Array.from(r.querySelectorAll('td')).map(c=>(c.textContent||'').trim())).filter(c=>c.length===2&&c[0].startsWith('stun:')).map(c=>({server:c[0],result:c[1]}));const link=Array.from(document.querySelectorAll('a[href]')).find(a=>{try{const u=new URL(a.href);return u.hostname==='ippure.com'&&u.searchParams.has('ip')}catch{return false}});return{url:location.href,rows,proxy_exit:link?(link.textContent||'').trim():null}})()`;
async function collect(config,guardDirectory){
 const profile=path.resolve(config.profile),marker=JSON.parse(fs.readFileSync(path.join(profile,'.proxy-env-doctor-scope.json')));
 if(marker.scope_id!==config.scope_id||!path.isAbsolute(config.edge)||config.detector_url!==URL_FIXED)throw Error('unregistered_detector');
 const portFile=path.join(profile,'DevToolsActivePort');if(fs.existsSync(portFile))fs.unlinkSync(portFile);
 const child=spawn(config.edge,['--headless=new','--remote-debugging-address=127.0.0.1','--remote-debugging-port=0','--user-data-dir='+profile,'--proxy-server='+config.proxy,'--force-webrtc-ip-handling-policy=disable_non_proxied_udp','--disable-quic','--no-first-run','--no-default-browser-check','about:blank'],{windowsHide:true,stdio:'ignore'});
 let browser,page,closed=false;const stop=async()=>{if(closed)return;closed=true;if(browser)await browser.call('Browser.close').catch(()=>{});page?.close();browser?.close();};
 // On abrupt caller exit, close our browser only when there is no latched pause.
 const isLatched=()=>{try{return ['switch_required','suspend_required'].includes(JSON.parse(fs.readFileSync(path.join(guardDirectory,'state.json'))).phase)}catch{return true}};
 process.stdin.on('end',()=>{if(!isLatched())void stop();});
 try{
  let port;
  for(let i=0;i<80;i++){if(child.exitCode!==null)throw Error('detector_browser_exited');if(fs.existsSync(portFile)){port=Number(fs.readFileSync(portFile,'utf8').split('\n')[0]);if(port>0&&port<65536)break;}await delay(200);}
  if(!port)throw Error('detector_start_timeout');
  const origin='http://127.0.0.1:'+port;
  const info=await getJSON(origin+'/json/version');browser=await CDP.connect(info.webSocketDebuggerUrl.replace('localhost','127.0.0.1'));
  const pages=await getJSON(origin+'/json/list');const target=pages.find(p=>p.type==='page'&&p.url==='about:blank');if(!target)throw Error('owned_blank_page_missing');
  page=await CDP.connect(target.webSocketDebuggerUrl.replace('localhost','127.0.0.1'));await page.call('Page.enable');
  const navigation=await page.call('Page.navigate',{url:URL_FIXED});if(navigation.errorText)throw Error('page_navigation_failed');
  const start=Date.now();let receipt=null,snapshot=null,stable=0,last='';
  while(Date.now()-start<45000){
   const route=await checkRoute(config.route_command);if(route.verified)receipt={...route,scope_id:config.scope_id,observed_at:Date.now()/1000};
   const result=await page.call('Runtime.evaluate',{expression:READ_DOM,returnByValue:true});snapshot=result.result?.value;
   atomic(path.join(guardDirectory,'native-diagnostic.json'),{pageExact:snapshot?.url===URL_FIXED,rowCount:snapshot?.rows?.length||0,channelVerified:!!receipt,elapsed_ms:Date.now()-start,jsException:!!result.exceptionDetails});
   if(snapshot?.url===URL_FIXED&&snapshot.rows?.length===9){const text=JSON.stringify(snapshot);stable=text===last?stable+1:0;last=text;if(stable>=2&&Date.now()-start>=15000&&receipt)break;}
   await delay(1000);
  }
  if(snapshot?.url!==URL_FIXED)throw Error('page_url_unverified');
  if(snapshot.rows?.length!==9)throw Error('page_rows_unavailable');
  if(!receipt)throw Error('dedicated_channel_unverified');
  atomic(path.join(guardDirectory,'native-channel.json'),receipt);
  const raw={source:'native-browser',extension_instance:config.collector_id,url:URL_FIXED,observed_at:Date.now()/1000,proxy_exit:snapshot.proxy_exit,rows:snapshot.rows};
  process.stdout.write(JSON.stringify({ok:true,raw})+'\n');
  // Keep this exact browser alive until the caller ingests and possibly pauses it.
  await new Promise(resolve=>{process.stdin.once('data',()=>resolve());process.stdin.once('end',()=>resolve());});
  if(!isLatched())await stop();
 }catch(error){if(!isLatched())await stop();throw error;}
}
module.exports={localURL,READ_DOM,checkRoute};
if(require.main===module){let c;try{const directory=path.resolve(process.argv[2]);c=JSON.parse(fs.readFileSync(path.join(directory,'native-config.json')));collect(c,directory).then(()=>process.exit(0)).catch(error=>{const code=/^[a-z_]{1,80}$/.test(error.message)?error.message:'native_page_collection_failed';process.stdout.write(JSON.stringify({ok:false,error:code})+'\n');process.exit(1)})}catch{process.stdout.write(JSON.stringify({ok:false,error:'native_configuration_invalid'})+'\n');process.exit(1)}}
