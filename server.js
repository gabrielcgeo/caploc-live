import {createServer} from 'node:http';
import {randomBytes, createHash, timingSafeEqual} from 'node:crypto';
import {readFile, writeFile, rename, mkdir, unlink} from 'node:fs/promises';
import {join} from 'node:path';

const port=Number(process.env.PORT||8080);
const dataDir=process.env.DATA_DIR||'/data';
const publicBase=(process.env.PUBLIC_BASE_URL||'').replace(/\/$/,'');
const adminToken=process.env.EXPLORER_ADMIN_TOKEN||'';
if(!/^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(publicBase)||adminToken.length<32) {
  console.error('Set PUBLIC_BASE_URL to an HTTPS origin and EXPLORER_ADMIN_TOKEN to 32+ random characters');
  process.exit(1);
}
await mkdir(dataDir,{recursive:true});
const tokenHash=value=>createHash('sha256').update(value).digest();
function equalHash(a,b) {
  const x=tokenHash(a),y=Buffer.from(b,'hex');
  return y.length===x.length&&timingSafeEqual(x,y);
}
function send(response,status,data,type='application/json; charset=utf-8') {
  response.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store',
    'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
    'Content-Security-Policy':type.startsWith('text/html')?
      "default-src 'none'; script-src https://unpkg.com 'unsafe-inline'; style-src https://unpkg.com 'unsafe-inline'; img-src https://unpkg.com https://*.tile.openstreetmap.org data:; connect-src 'self'":
      "default-src 'none'"});
  response.end(type.startsWith('application/json')?JSON.stringify(data):data);
}
async function body(request) {
  let bytes=0,text='';
  for await(const chunk of request) {
    bytes+=chunk.length;
    if(bytes>4096) throw new Error('body_too_large');
    text+=chunk;
  }
  return JSON.parse(text||'{}');
}
const idPattern=/^[A-Za-z0-9_-]{22}$/;
function pathFor(id) { if(!idPattern.test(id)) throw new Error('invalid_id'); return join(dataDir,id+'.json'); }
async function load(id) {
  try {
    const record=JSON.parse(await readFile(pathFor(id),'utf8'));
    if(Date.now()>record.expiresAt) { await unlink(pathFor(id)); return null; }
    return record;
  }
  catch(error) { if(error.code==='ENOENT') return null; throw error; }
}
async function save(record) {
  const file=pathFor(record.id),temporary=file+'.tmp';
  await writeFile(temporary,JSON.stringify(record),{mode:0o600});
  await rename(temporary,file);
}
function bearer(request) { const value=request.headers.authorization||''; return value.startsWith('Bearer ')?value.slice(7):''; }
const token=()=>randomBytes(32).toString('base64url');
function viewer(id) { return `<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CapLoc · localização compartilhada</title><link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"><style>html,body,#map{height:100%;margin:0;font:16px system-ui}#info{position:absolute;z-index:1000;top:12px;left:12px;right:12px;max-width:440px;padding:13px;border-radius:14px;background:#fff;color:#15233a;box-shadow:0 2px 12px #0004}small{color:#53657a}.stale{color:#a23b16;font-weight:700}.fresh{color:#176933;font-weight:700}</style><div id="map"></div><div id="info">Carregando localização…</div><script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script><script>const map=L.map('map').setView([-19.92,-43.94],14);L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{attribution:'© OpenStreetMap contributors',maxZoom:19}).addTo(map);let marker,circle,line,first=true;async function refresh(){try{let r=await fetch('/api/public/${id}',{cache:'no-store'});if(r.status===204){document.getElementById('info').textContent='Aguardando primeira posição do telefone…';return}if(!r.ok)throw Error(r.status===410?'Link expirado':'Localização indisponível');let d=await r.json();let p=d.position;let coord=[p.lat,p.lon];if(!marker){marker=L.marker(coord).addTo(map);circle=L.circle(coord,{radius:p.accuracy||0,color:'#1769e8'}).addTo(map);line=L.polyline([],{color:'#1769e8',weight:4}).addTo(map)}else{marker.setLatLng(coord);circle.setLatLng(coord).setRadius(p.accuracy||0)}line.setLatLngs(d.points.map(x=>[x.lat,x.lon]));if(first){map.setView(coord,16);first=false}let age=Math.max(0,Math.floor((Date.now()-p.at)/1000));let stale=age>45;let status=stale?'Sem atualização há '+(age<120?age+' segundos':Math.floor(age/60)+' minutos')+' · última posição conhecida':'Posição atualizada há '+age+' segundos';document.getElementById('info').innerHTML='<b>'+d.name.replace(/[&<>"']/g,'')+'</b><br><span class="'+(stale?'stale':'fresh')+'">'+status+'</span><br>Recebida: '+new Date(p.at).toLocaleString('pt-BR')+'<br><small>Precisão GPS estimada: ±'+Math.round(p.accuracy||0)+' m</small>'}catch(e){document.getElementById('info').textContent=e.message}}refresh();setInterval(refresh,15000)</script></html>`; }
const server=createServer(async(request,response)=>{
  try {
    const url=new URL(request.url,'http://localhost');
    if(request.method==='GET'&&url.pathname==='/health') return send(response,200,{ok:true});
    if(request.method==='POST'&&url.pathname==='/api/sessions') {
      if(!equalHash(bearer(request),tokenHash(adminToken).toString('hex'))) return send(response,401,{error:'unauthorized'});
      const input=await body(request);
      const hours=Number(input.ttlHours||12);
      if(!Number.isFinite(hours)||hours<1||hours>24) return send(response,400,{error:'invalid_ttl'});
      const id=randomBytes(16).toString('base64url'),uploadToken=token();
      const record={id,name:String(input.name||'CapLoc Explorer').slice(0,80),
        uploadHash:tokenHash(uploadToken).toString('hex'),expiresAt:Date.now()+hours*3600000,
        active:true,points:[],position:null};
      await save(record);
      return send(response,201,{id,uploadToken,viewerUrl:publicBase+'/s/'+id,expiresAt:record.expiresAt});
    }
    const update=url.pathname.match(/^\/api\/sessions\/([A-Za-z0-9_-]{22})\/position$/);
    const stop=url.pathname.match(/^\/api\/sessions\/([A-Za-z0-9_-]{22})$/);
    if((request.method==='PUT'&&update)||(request.method==='DELETE'&&stop)) {
      const record=await load((update||stop)[1]);
      if(!record) return send(response,404,{error:'not_found'});
      if(!equalHash(bearer(request),record.uploadHash)) return send(response,401,{error:'unauthorized'});
      if(Date.now()>record.expiresAt) return send(response,410,{error:'expired'});
      if(request.method==='DELETE') {record.active=false;await save(record);return send(response,200,{ok:true});}
      if(!record.active) return send(response,409,{error:'ended'});
      const input=await body(request),lat=Number(input.lat),lon=Number(input.lon),accuracy=Number(input.accuracy);
      if(!Number.isFinite(lat)||!Number.isFinite(lon)||lat< -90||lat>90||lon< -180||lon>180||
         !Number.isFinite(accuracy)||accuracy<0||accuracy>10000) return send(response,400,{error:'invalid_position'});
      const point={lat,lon,accuracy,at:Date.now()};record.position=point;
      record.points.push(point);if(record.points.length>2000) record.points.splice(0,record.points.length-2000);
      await save(record);return send(response,200,{ok:true,at:point.at});
    }
    const publicMatch=url.pathname.match(/^\/api\/public\/([A-Za-z0-9_-]{22})$/);
    const pageMatch=url.pathname.match(/^\/s\/([A-Za-z0-9_-]{22})$/);
    if(request.method==='GET'&&(publicMatch||pageMatch)) {
      const record=await load((publicMatch||pageMatch)[1]);
      if(!record) return send(response,404,{error:'not_found'});
      if(!record.active) return send(response,410,{error:'ended'});
      if(pageMatch) return send(response,200,viewer(record.id),'text/html; charset=utf-8');
      if(!record.position) return send(response,204,'','text/plain');
      return send(response,200,{name:record.name,active:record.active,
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
