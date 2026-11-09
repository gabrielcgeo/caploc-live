import {timingSafeEqual,createHash} from 'node:crypto';

// One live base stream. RTCM is forwarded unchanged and never written to disk.
export function createRtcmRelay(sourceSecret,roverSecret) {
  const sourceExpected=createHash('sha256').update(sourceSecret||'').digest();
  const roverExpected=createHash('sha256').update(roverSecret||'').digest();
  let source=null,sourceSession='',clients=new Set(),lastFrameAt=0,frames=0,bytes=0;
  const authorized=(request,role)=>{
    const header=request.headers.authorization||'';
    let supplied='';
    if(header.startsWith('Bearer ')) supplied=header.slice(7);
    else if(header.startsWith('Basic ')) {
      try { supplied=Buffer.from(header.slice(6),'base64').toString('utf8').split(':').slice(1).join(':'); }
      catch { return false; }
    }
    const actual=createHash('sha256').update(supplied).digest();
    const secret=role==='source'?sourceSecret:roverSecret;
    const expected=role==='source'?sourceExpected:roverExpected;
    return secret?.length>=32&&timingSafeEqual(actual,expected);
  };
  const closeClients=()=>{for(const client of clients)client.end();clients.clear();};
  function status() {return {sourceConnected:!!source,rovers:clients.size,lastFrameAt,frames,bytes};}
  function handle(request,response,path) {
    if(!['/api/rtcm/CAPLOC','/api/rtcm/CAPLOC/status',
      '/api/rtcm/CAPLOC/source-status'].includes(path))return false;
    const role=request.method==='POST'||path.endsWith('/source-status')?'source':'rover';
    if(!authorized(request,role)) {
      response.writeHead(401,{'WWW-Authenticate':'Basic realm="CapLoc RTCM"','Cache-Control':'no-store'});
      response.end();return true;
    }
    if(path.endsWith('/status')||path.endsWith('/source-status')) {
      if(request.method!=='GET') {response.writeHead(405);response.end();return true;}
      if(path.endsWith('/source-status')&&(!source||!sourceSession||
          request.headers['x-caploc-source-session']!==sourceSession)) {
        response.writeHead(409,{'Cache-Control':'no-store'});response.end();return true;
      }
      response.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});
      response.end(JSON.stringify(status()));return true;
    }
    if(request.method==='POST') {
      if(source) {response.writeHead(409);response.end('base already connected');return true;}
      source=request;sourceSession=String(request.headers['x-caploc-source-session']||'');
      frames=0;bytes=0;lastFrameAt=0;
      request.setTimeout(30000,()=>request.destroy());
      response.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});
      response.flushHeaders();
      let buffer=Buffer.alloc(0);
      request.on('data',chunk=>{
        if(source!==request)return;
        buffer=Buffer.concat([buffer,chunk]);
        while(buffer.length>=3) {
          if(buffer[0]!==0xd3||(buffer[1]&0xfc)!==0) {buffer=buffer.subarray(1);continue;}
          const size=(((buffer[1]&3)<<8)|buffer[2])+6;
          if(buffer.length<size)break;
          const frame=buffer.subarray(0,size);
          if(crc24q(frame,frame.length-3)===frame.readUIntBE(frame.length-3,3)) {
            frames++;bytes+=size;lastFrameAt=Date.now();
            for(const client of clients) {
              if(!client.write(frame)) {clients.delete(client);client.destroy();}
            }
            buffer=buffer.subarray(size);
          } else buffer=buffer.subarray(1);
        }
        if(buffer.length>2048)buffer=buffer.subarray(-2048);
      });
      const finish=()=>{if(source===request){source=null;sourceSession='';closeClients();}response.end();};
      request.once('end',finish);request.once('close',finish);
      return true;
    }
    if(request.method==='GET') {
      if(!source||!lastFrameAt||Date.now()-lastFrameAt>15000) {
        response.writeHead(503,{'Cache-Control':'no-store','Retry-After':'2'});
        response.end('base stream unavailable');return true;
      }
      response.writeHead(200,{'Content-Type':'gnss/data','Cache-Control':'no-store',
        'Ntrip-Version':'Ntrip/2.0','X-Accel-Buffering':'no'});
      response.flushHeaders();clients.add(response);
      request.once('close',()=>clients.delete(response));
      return true;
    }
    response.writeHead(405);response.end();return true;
  }
  return {handle,status};
}

function crc24q(buffer,length) {
  let crc=0;
  for(let i=0;i<length;i++) {
    crc^=buffer[i]<<16;
    for(let bit=0;bit<8;bit++) {crc<<=1;if(crc&0x1000000)crc^=0x1864cfb;}
  }
  return crc&0xffffff;
}
