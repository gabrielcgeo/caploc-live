import {createServer} from 'node:http';
import {randomBytes, createHash, createCipheriv, createDecipheriv, timingSafeEqual, scryptSync} from 'node:crypto';
import {readFile, writeFile, rename, mkdir, unlink, readdir} from 'node:fs/promises';
import {join} from 'node:path';
import QRCode from 'qrcode';

const port=Number(process.env.PORT||8080);
const dataDir=process.env.DATA_DIR||'/data';
const publicBase=(process.env.PUBLIC_BASE_URL||'').replace(/\/$/,'');
const adminToken=process.env.EXPLORER_ADMIN_TOKEN||'';
const monitorEmail=(process.env.MONITOR_ADMIN_EMAIL||'').trim().toLowerCase();
const monitorPasswordHash=process.env.MONITOR_ADMIN_PASSWORD_SCRYPT||'';
if(!/^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(publicBase)||adminToken.length<32) {
  console.error('Set PUBLIC_BASE_URL to an HTTPS origin and EXPLORER_ADMIN_TOKEN to 32+ random characters');
  process.exit(1);
}
await mkdir(dataDir,{recursive:true});
const dataKey=createHash('sha256').update('caploc-location-v1:').update(adminToken).digest();
function seal(record) {
  const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',dataKey,iv);
  const ciphertext=Buffer.concat([cipher.update(JSON.stringify(record),'utf8'),cipher.final()]);
  return JSON.stringify({v:1,iv:iv.toString('base64url'),body:ciphertext.toString('base64url'),
    tag:cipher.getAuthTag().toString('base64url')});
}
function unseal(raw) {
  const envelope=JSON.parse(raw);
  if(envelope.v!==1) return envelope;
  const decipher=createDecipheriv('aes-256-gcm',dataKey,Buffer.from(envelope.iv,'base64url'));
  decipher.setAuthTag(Buffer.from(envelope.tag,'base64url'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.body,'base64url')),
    decipher.final()]).toString('utf8'));
}
const tokenHash=value=>createHash('sha256').update(value).digest();
function equalHash(a,b) {
  const x=tokenHash(a),y=Buffer.from(b,'hex');
  return y.length===x.length&&timingSafeEqual(x,y);
}
function send(response,status,data,type='application/json; charset=utf-8',extraHeaders={}) {
  response.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store',
    'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
    'X-Frame-Options':'DENY',...extraHeaders,
    'Content-Security-Policy':type.startsWith('text/html')?
      "default-src 'none'; script-src https://unpkg.com 'unsafe-inline'; style-src https://unpkg.com 'unsafe-inline'; img-src https://unpkg.com https://*.tile.openstreetmap.org https://mt1.google.com data:; connect-src 'self'":
      "default-src 'none'"});
  response.end(type.startsWith('application/json')?JSON.stringify(data):data);
}
async function body(request,maxBytes=4096) {
  let bytes=0,text='';
  for await(const chunk of request) {
    bytes+=chunk.length;
    if(bytes>maxBytes) throw new Error('body_too_large');
    text+=chunk;
  }
  return JSON.parse(text||'{}');
}
function sendBinary(response,status,data,mime) {
  response.writeHead(status,{'Content-Type':mime,'Content-Length':data.length,
    'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
    'Content-Security-Policy':"default-src 'none'",'Referrer-Policy':'no-referrer'});
  response.end(data);
}
const idPattern=/^[A-Za-z0-9_-]{43}$/;
function pathFor(id) { if(!idPattern.test(id)) throw new Error('invalid_id'); return join(dataDir,id+'.json'); }
async function load(id) {
  try {
    const record=unseal(await readFile(pathFor(id),'utf8'));
    if(Date.now()>record.expiresAt) { await unlink(pathFor(id)); return null; }
    return record;
  }
  catch(error) { if(error.code==='ENOENT') return null; throw error; }
}
async function save(record) {
  const file=pathFor(record.id),temporary=file+'.tmp';
  await writeFile(temporary,seal(record),{mode:0o600});
  await rename(temporary,file);
}
function bearer(request) { const value=request.headers.authorization||''; return value.startsWith('Bearer ')?value.slice(7):''; }
const token=()=>randomBytes(32).toString('base64url');
const monitorSessions=new Map(),monitorAttempts=new Map();
const monitorCookie='caploc_monitor';
function enrollmentPath(code) {
  if(!/^[A-Za-z0-9_-]{24}$/.test(code))return null;
  return join(dataDir,'enroll-'+tokenHash(code).toString('hex')+'.json');
}
async function saveEnrollmentCode(code,expiresAt) {
  await writeFile(enrollmentPath(code),seal({expiresAt}),{mode:0o600,flag:'wx'});
}
async function enrollmentExpiry(code) {
  const path=enrollmentPath(code);if(!path)return 0;
  try {
    const expiresAt=unseal(await readFile(path,'utf8')).expiresAt;
    if(expiresAt>Date.now())return expiresAt;
    await unlink(path);return 0;
  } catch(error) {if(error.code==='ENOENT')return 0;throw error;}
}
function monitorAuthenticated(request) {
  const cookie=(request.headers.cookie||'').split(';').map(v=>v.trim())
    .find(v=>v.startsWith(monitorCookie+'='));
  const session=cookie&&monitorSessions.get(cookie.slice(monitorCookie.length+1));
  if(!session||session<Date.now()) return false;
  return true;
}
function validMonitorPassword(password) {
  const parts=monitorPasswordHash.split(':');
  if(parts.length!==2||!parts[0]||!parts[1]) return false;
  const expected=Buffer.from(parts[1],'hex');
  if(expected.length!==32) return false;
  const actual=scryptSync(password+':'+adminToken,parts[0],32);
  return timingSafeEqual(actual,expected);
}
function loginAllowed(request) {
  const ip=String(request.socket.remoteAddress||'unknown');
  const recent=(monitorAttempts.get(ip)||[]).filter(at=>at>Date.now()-900000);
  if(recent.length>=5) return false;
  recent.push(Date.now());monitorAttempts.set(ip,recent);
  return true;
}
async function monitoredRecords() {
  const files=(await readdir(dataDir)).filter(name=>idPattern.test(name.slice(0,-5))&&name.endsWith('.json'));
  const records=[];
  for(const name of files) {
    try {
      const record=await load(name.slice(0,-5));
      if(record?.monitoringEnabled) records.push(record);
    } catch(error) { console.error('Monitor record unavailable',error); }
  }
  return records.sort((a,b)=>(b.position?.at||0)-(a.position?.at||0));
}
function fleetPath(id) { if(!idPattern.test(id)) throw new Error('invalid_id'); return join(dataDir,'fleet-'+id+'.json'); }
async function loadFleet(id) {
  try { return unseal(await readFile(fleetPath(id),'utf8')); }
  catch(error) { if(error.code==='ENOENT') return null; throw error; }
}
async function saveFleet(record) {
  const file=fleetPath(record.id),temporary=file+'.tmp';
  await writeFile(temporary,seal(record),{mode:0o600});await rename(temporary,file);
}
async function fleetRecords() {
  const files=(await readdir(dataDir)).filter(name=>/^fleet-[A-Za-z0-9_-]{43}\.json$/.test(name));
  const records=[];
  for(const name of files) {
    try { const record=await loadFleet(name.slice(6,-5));if(record)records.push(record); }
    catch(error) { console.error('Fleet record unavailable',error); }
  }
  return records.sort((a,b)=>(b.position?.at||0)-(a.position?.at||0));
}
function incidentPath(id) { if(!idPattern.test(id)) throw new Error('invalid_id'); return join(dataDir,'incident-'+id+'.json'); }
async function loadIncident(id) {
  try {return unseal(await readFile(incidentPath(id),'utf8'));}
  catch(error) {if(error.code==='ENOENT')return null;throw error;}
}
async function saveIncident(record) {
  const file=incidentPath(record.id),temporary=file+'.tmp';
  await writeFile(temporary,seal(record),{mode:0o600});await rename(temporary,file);
}
async function incidentRecords() {
  const files=(await readdir(dataDir)).filter(name=>/^incident-[A-Za-z0-9_-]{43}\.json$/.test(name));
  const records=[];
  for(const name of files) {
    try {const record=await loadIncident(name.slice(9,-5));if(record)records.push(record);}
    catch(error){console.error('Incident unavailable',error)}
  }
  return records.sort((a,b)=>b.at-a.at).slice(0,200);
}
const publicCreates=new Map();
let globalCreates=[];
const weatherCache=new Map();
const careCache=new Map(),careInFlight=new Map();
let careQueue=Promise.resolve(),lastCareAt=0,careRequests=[];
async function nearbyCare(latitude,longitude) {
  // Coarse cell prevents transmitting a user's exact GPS position upstream.
  const lat=Math.round(latitude*50)/50,lon=Math.round(longitude*50)/50;
  const key=lat.toFixed(2)+','+lon.toFixed(2),now=Date.now();
  const cached=careCache.get(key);
  if(cached&&cached.expires>now) return cached.value;
  if(careInFlight.has(key)) return careInFlight.get(key);
  careRequests=careRequests.filter(at=>at>now-3600000);
  if(careRequests.length>=60) throw new Error('care_rate_limited');
  careRequests.push(now);
  const job=(async()=>{
    const previous=careQueue;
    let release;
    careQueue=new Promise(resolve=>{release=resolve});
    await previous;
    try {
      const pause=Math.max(0,1100-(Date.now()-lastCareAt));
      if(pause) await new Promise(resolve=>setTimeout(resolve,pause));
      lastCareAt=Date.now();
      const box=[lon-0.27,lat+0.27,lon+0.27,lat-0.27].map(v=>v.toFixed(6)).join(',');
      const url='https://nominatim.openstreetmap.org/search?format=jsonv2&q=hospital'+
        '&limit=40&bounded=1&addressdetails=1&viewbox='+encodeURIComponent(box);
      const response=await fetch(url,{headers:{'User-Agent':'CapLoc/0.37 (+https://caploc.safeclim.com)',
        'Accept-Language':'pt-BR,pt;q=0.9'},signal:AbortSignal.timeout(15000)});
      if(!response.ok) throw new Error('care_upstream_unavailable');
      const value=await response.json();
      if(!Array.isArray(value)) throw new Error('care_upstream_invalid');
      careCache.set(key,{value,expires:Date.now()+900000});
      if(careCache.size>300) careCache.delete(careCache.keys().next().value);
      return value;
    } finally {release()}
  })();
  careInFlight.set(key,job);
  try {return await job} finally {careInFlight.delete(key)}
}
function mayCreate(request) {
  const now=Date.now(),hourAgo=now-3600000;
  globalCreates=globalCreates.filter(at=>at>hourAgo);
  const ip=String(request.headers['x-forwarded-for']||request.socket.remoteAddress||'unknown')
    .split(',')[0].trim().slice(0,80);
  const recent=(publicCreates.get(ip)||[]).filter(at=>at>hourAgo);
  if(globalCreates.length>=60||recent.length>=8) return false;
  recent.push(now);publicCreates.set(ip,recent);globalCreates.push(now);
  return true;
}
async function createSession(input,monitorAllowed=false) {
  const hours=Number(input.ttlHours||12);
  if(!Number.isFinite(hours)||hours<1||hours>24) return null;
  const id=randomBytes(32).toString('base64url'),uploadToken=token();
  const record={id,name:String(input.name||'CapLoc Explorer').slice(0,80),
    uploadHash:tokenHash(uploadToken).toString('hex'),expiresAt:Date.now()+hours*3600000,
    active:true,monitoringEnabled:monitorAllowed&&input.monitoringEnabled===true,points:[],position:null};
  await save(record);
  return {id,uploadToken,viewerUrl:publicBase+'/s/'+id,expiresAt:record.expiresAt};
}
async function weatherFor(point) {
  const lat=Math.round(point.lat*100)/100,lon=Math.round(point.lon*100)/100;
  const key=lat+','+lon,cached=weatherCache.get(key),now=Date.now();
  if(cached&&cached.expires>now) return cached.value;
  const url='https://api.open-meteo.com/v1/forecast?latitude='+lat+'&longitude='+lon+
    '&current=temperature_2m,relative_humidity_2m,precipitation,weather_code,wind_speed_10m'+
    '&hourly=precipitation_probability&forecast_days=1&timezone=auto';
  const response=await fetch(url,{signal:AbortSignal.timeout(8000)});
  if(!response.ok) throw new Error('weather_unavailable');
  const data=await response.json();
  const value={current:data.current||null,hourly:data.hourly||null,at:now};
  weatherCache.set(key,{expires:now+600000,value});
  return value;
}
const viewerTemplate=await readFile(new URL('./viewer.html',import.meta.url),'utf8');
const monitorTemplate=await readFile(new URL('./monitor.html',import.meta.url),'utf8');
function viewer(id) { return viewerTemplate.replaceAll('__SESSION_ID__',id); }
const server=createServer(async(request,response)=>{
  try {
    const url=new URL(request.url,'http://localhost');
    if(request.method==='GET'&&url.pathname==='/health') return send(response,200,{ok:true});
    if(request.method==='GET'&&url.pathname==='/central')
      return send(response,200,monitorTemplate,'text/html; charset=utf-8');
    if(request.method==='POST'&&url.pathname==='/api/monitor/login') {
      if(!loginAllowed(request)) return send(response,429,{error:'too_many_attempts'});
      const input=await body(request);
      if(!monitorEmail||!validMonitorPassword(String(input.password||''))||
          String(input.email||'').trim().toLowerCase()!==monitorEmail)
        return send(response,401,{error:'invalid_credentials'});
      const session=token();monitorSessions.set(session,Date.now()+8*3600000);
      return send(response,200,{ok:true},'application/json; charset=utf-8',
        {'Set-Cookie':`${monitorCookie}=${session}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`});
    }
    if(request.method==='POST'&&url.pathname==='/api/monitor/logout') {
      const cookie=(request.headers.cookie||'').split(';').map(v=>v.trim())
        .find(v=>v.startsWith(monitorCookie+'='));
      if(cookie) monitorSessions.delete(cookie.slice(monitorCookie.length+1));
      return send(response,200,{ok:true},'application/json; charset=utf-8',
        {'Set-Cookie':`${monitorCookie}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`});
    }
    if(request.method==='POST'&&url.pathname==='/api/monitor/enroll-codes') {
      if(!monitorAuthenticated(request)) return send(response,401,{error:'unauthorized'});
      const code=randomBytes(18).toString('base64url');
      const expiresAt=Date.now()+2*60*60*1000;
      await saveEnrollmentCode(code,expiresAt);
      const qr=await QRCode.toDataURL('caploc://fleet/enroll?code='+code,
        {errorCorrectionLevel:'M',margin:2,width:320});
      return send(response,201,{code,expiresAt,qr});
    }
    if(request.method==='POST'&&url.pathname==='/api/fleet/enroll') {
      const input=await body(request),code=String(input.code||'').trim();
      const expires=await enrollmentExpiry(code);
      if(!expires||expires<Date.now()) return send(response,401,{error:'invalid_code'});
      const name=String(input.name||'').trim().slice(0,80);
      if(name.length<2) return send(response,400,{error:'invalid_name'});
      const id=token(),deviceToken=token();
      await saveFleet({id,name,tokenHash:tokenHash(deviceToken).toString('hex'),
        enrolledAt:Date.now(),active:true,position:null,points:[]});
      return send(response,201,{id,deviceToken,name});
    }
    const incidentUpload=url.pathname.match(/^\/api\/fleet\/([A-Za-z0-9_-]{43})\/incidents$/);
    if(request.method==='POST'&&incidentUpload) {
      const device=await loadFleet(incidentUpload[1]);
      if(!device)return send(response,404,{error:'not_found'});
      if(!equalHash(bearer(request),device.tokenHash)||!device.active)
        return send(response,401,{error:'unauthorized'});
      const input=await body(request,12*1024*1024);
      const message=String(input.message||'').trim().slice(0,2000);
      const mime=String(input.mime||'');
      const allowed=/^(image\/(jpeg|png|webp|heic|heif)|video\/(mp4|webm|quicktime|3gpp)|audio\/(mpeg|mp4|ogg|wav|x-wav|3gpp|amr|aac))$/;
      const media=String(input.media||'');
      if((!message&&!media)||(media&&(!allowed.test(mime)||media.length>11*1024*1024||
          Buffer.from(media,'base64').length>8*1024*1024)))
        return send(response,400,{error:'invalid_incident'});
      let position=null;
      if(input.position) {
        const lat=Number(input.position.lat),lon=Number(input.position.lon);
        if(Number.isFinite(lat)&&Number.isFinite(lon)&&Math.abs(lat)<=90&&Math.abs(lon)<=180)
          position={lat,lon};
      }
      const record={id:token(),deviceId:device.id,deviceName:device.name,at:Date.now(),
        message,mime:media?mime:null,media:media||null,position};
      await saveIncident(record);return send(response,201,{id:record.id,at:record.at});
    }
    if(request.method==='GET'&&url.pathname==='/api/monitor/incidents') {
      if(!monitorAuthenticated(request))return send(response,401,{error:'unauthorized'});
      const incidents=await incidentRecords();
      return send(response,200,incidents.map(({media,...rest})=>({...rest,hasMedia:!!media})));
    }
    const mediaMatch=url.pathname.match(/^\/api\/monitor\/incidents\/([A-Za-z0-9_-]{43})\/media$/);
    if(request.method==='GET'&&mediaMatch) {
      if(!monitorAuthenticated(request))return send(response,401,{error:'unauthorized'});
      const incident=await loadIncident(mediaMatch[1]);
      if(!incident?.media)return send(response,404,{error:'not_found'});
      return sendBinary(response,200,Buffer.from(incident.media,'base64'),incident.mime);
    }
    const fleetUpdate=url.pathname.match(/^\/api\/fleet\/([A-Za-z0-9_-]{43})\/position$/);
    const fleetStop=url.pathname.match(/^\/api\/fleet\/([A-Za-z0-9_-]{43})$/);
    if((request.method==='PUT'&&fleetUpdate)||(request.method==='DELETE'&&fleetStop)) {
      const record=await loadFleet((fleetUpdate||fleetStop)[1]);
      if(!record) return send(response,404,{error:'not_found'});
      if(!equalHash(bearer(request),record.tokenHash)) return send(response,401,{error:'unauthorized'});
      if(!record.active) return send(response,409,{error:'revoked'});
      if(request.method==='DELETE') {
        record.active=false;record.endedAt=Date.now();await saveFleet(record);
        return send(response,200,{ok:true});
      }
      const input=await body(request),lat=Number(input.lat),lon=Number(input.lon),accuracy=Number(input.accuracy);
      if(!Number.isFinite(lat)||!Number.isFinite(lon)||lat< -90||lat>90||lon< -180||lon>180||
         !Number.isFinite(accuracy)||accuracy<0||accuracy>10000)
        return send(response,400,{error:'invalid_position'});
      const point={lat,lon,accuracy,at:Date.now()};record.position=point;
      record.points.push(point);if(record.points.length>2000)record.points.splice(0,record.points.length-2000);
      await saveFleet(record);return send(response,200,{ok:true,at:point.at});
    }
    const fleetRevoke=url.pathname.match(/^\/api\/monitor\/fleet\/([A-Za-z0-9_-]{43})$/);
    if(request.method==='DELETE'&&fleetRevoke) {
      if(!monitorAuthenticated(request)) return send(response,401,{error:'unauthorized'});
      const record=await loadFleet(fleetRevoke[1]);
      if(!record) return send(response,404,{error:'not_found'});
      record.active=false;record.endedAt=Date.now();await saveFleet(record);
      return send(response,200,{ok:true});
    }
    if(request.method==='GET'&&url.pathname==='/api/monitor/sessions') {
      if(!monitorAuthenticated(request)) return send(response,401,{error:'unauthorized'});
      const [sessions,fleet]=await Promise.all([monitoredRecords(),fleetRecords()]);
      return send(response,200,[...fleet.map(r=>({id:r.id,kind:'fleet',name:r.name,active:r.active,
        expiresAt:null,endedAt:r.endedAt||null,endReason:null,
        position:r.position,pointCount:r.points.length})),
        ...sessions.map(r=>({id:r.id,kind:'session',name:r.name,active:r.active,
        expiresAt:r.expiresAt,endedAt:r.endedAt||null,endReason:r.endReason||null,
        position:r.position,pointCount:r.points.length}))]);
    }
    const monitorDetail=url.pathname.match(/^\/api\/monitor\/sessions\/([A-Za-z0-9_-]{43})$/);
    if(request.method==='GET'&&monitorDetail) {
      if(!monitorAuthenticated(request)) return send(response,401,{error:'unauthorized'});
      let record=await loadFleet(monitorDetail[1]);
      let kind='fleet';
      if(!record) {record=await load(monitorDetail[1]);kind='session';}
      if(!record||(kind==='session'&&!record.monitoringEnabled)) return send(response,404,{error:'not_found'});
      return send(response,200,{id:record.id,kind,name:record.name,active:record.active,
        expiresAt:record.expiresAt,endedAt:record.endedAt||null,endReason:record.endReason||null,
        position:record.position,points:record.points});
    }
    if(request.method==='GET'&&url.pathname==='/api/nearby-care') {
      const lat=Number(url.searchParams.get('lat')),lon=Number(url.searchParams.get('lon'));
      if(!url.searchParams.has('lat')||!url.searchParams.has('lon')||
         !Number.isFinite(lat)||!Number.isFinite(lon)||lat< -90||lat>90||lon< -180||lon>180)
        return send(response,400,{error:'invalid_position'});
      try {return send(response,200,await nearbyCare(lat,lon));}
      catch(error) {return send(response,error.message==='care_rate_limited'?429:503,
        {error:'care_unavailable'});}
    }
    if(request.method==='POST'&&(url.pathname==='/api/sessions'||url.pathname==='/api/public-sessions')) {
      const anonymous=url.pathname==='/api/public-sessions';
      if(!anonymous&&!equalHash(bearer(request),tokenHash(adminToken).toString('hex')))
        return send(response,401,{error:'unauthorized'});
      if(anonymous&&!mayCreate(request)) return send(response,429,{error:'rate_limited'});
      const created=await createSession(await body(request),!anonymous);
      return created?send(response,201,created):send(response,400,{error:'invalid_ttl'});
    }
    const update=url.pathname.match(/^\/api\/sessions\/([A-Za-z0-9_-]{43})\/position$/);
    const stop=url.pathname.match(/^\/api\/sessions\/([A-Za-z0-9_-]{43})$/);
    if((request.method==='PUT'&&update)||(request.method==='DELETE'&&stop)) {
      const record=await load((update||stop)[1]);
      if(!record) return send(response,404,{error:'not_found'});
      if(!equalHash(bearer(request),record.uploadHash)) return send(response,401,{error:'unauthorized'});
      if(Date.now()>record.expiresAt) return send(response,410,{error:'expired'});
      if(request.method==='DELETE') {
        const input=await body(request);
        record.active=false;record.endedAt=Date.now();
        record.endReason=String(input.reason||'Compartilhamento encerrado').slice(0,120);
        await save(record);return send(response,200,{ok:true});
      }
      if(!record.active) return send(response,409,{error:'ended'});
      const input=await body(request),lat=Number(input.lat),lon=Number(input.lon),accuracy=Number(input.accuracy);
      if(!Number.isFinite(lat)||!Number.isFinite(lon)||lat< -90||lat>90||lon< -180||lon>180||
         !Number.isFinite(accuracy)||accuracy<0||accuracy>10000) return send(response,400,{error:'invalid_position'});
      const point={lat,lon,accuracy,at:Date.now()};record.position=point;
      record.points.push(point);if(record.points.length>2000) record.points.splice(0,record.points.length-2000);
      await save(record);return send(response,200,{ok:true,at:point.at});
    }
    const publicMatch=url.pathname.match(/^\/api\/public\/([A-Za-z0-9_-]{43})$/);
    const weatherMatch=url.pathname.match(/^\/api\/public\/([A-Za-z0-9_-]{43})\/weather$/);
    const pageMatch=url.pathname.match(/^\/s\/([A-Za-z0-9_-]{43})$/);
    if(request.method==='GET'&&weatherMatch) {
      const record=await load(weatherMatch[1]);
      if(!record||!record.position) return send(response,404,{error:'not_found'});
      try { return send(response,200,await weatherFor(record.position)); }
      catch { return send(response,503,{error:'weather_unavailable'}); }
    }
    if(request.method==='GET'&&(publicMatch||pageMatch)) {
      const record=await load((publicMatch||pageMatch)[1]);
      if(!record) return send(response,404,{error:'not_found'});
      if(pageMatch) return send(response,200,viewer(record.id),'text/html; charset=utf-8');
      if(!record.position) return send(response,204,'','text/plain');
      return send(response,200,{name:record.name,active:record.active,
        endedAt:record.endedAt||null,endReason:record.endReason||null,
        position:record.position,points:record.points});
    }
    return send(response,404,{error:'not_found'});
  } catch(error) {
    const code=error.message==='body_too_large'?413:error instanceof SyntaxError?400:500;
    if(code===500) console.error('Request failed',error);
    send(response,code,{error:code===500?'server_error':'invalid_request'});
  }
});
server.listen(port,'0.0.0.0',()=>console.log(`CapLoc Explorer Live listening on ${port}`));
