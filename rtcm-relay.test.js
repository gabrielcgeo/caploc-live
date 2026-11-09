import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,request as httpRequest} from 'node:http';
import {createRtcmRelay} from './rtcm-relay.js';

const token='local-test-rtcm-secret-at-least-32-characters';
const roverToken='different-rover-secret-at-least-32-characters';
function frame(payload) {
  const bytes=Buffer.from([0xd3,0,payload.length,...payload,0,0,0]);
  let crc=0;
  for(let i=0;i<bytes.length-3;i++) {
    crc^=bytes[i]<<16;
    for(let bit=0;bit<8;bit++){crc<<=1;if(crc&0x1000000)crc^=0x1864cfb;}
  }
  bytes.writeUIntBE(crc&0xffffff,bytes.length-3,3);return bytes;
}
test('authenticated live RTCM relay validates CRC and streams to rover',async()=>{
  const relay=createRtcmRelay(token,roverToken);
  const server=createServer((req,res)=>{if(!relay.handle(req,res,new URL(req.url,'http://local').pathname)){
    res.writeHead(404);res.end();}});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const port=server.address().port,base=`http://127.0.0.1:${port}`;
  const auth={'Authorization':'Bearer '+token};
  const sourceSession='test-session-for-source-check';
  const sourceAuth={...auth,'X-CapLoc-Source-Session':sourceSession};
  const roverAuth={'Authorization':'Bearer '+roverToken};
  let source;
  try {
    assert.equal((await fetch(base+'/api/rtcm/CAPLOC')).status,401);
    assert.equal((await fetch(base+'/api/rtcm/CAPLOC',{headers:auth})).status,401);
    assert.equal((await fetch(base+'/api/rtcm/CAPLOC',{headers:roverAuth})).status,503);
    assert.equal((await fetch(base+'/api/rtcm/CAPLOC/source-status',{headers:roverAuth})).status,401);
    assert.equal((await fetch(base+'/api/rtcm/CAPLOC/source-status',{headers:sourceAuth})).status,409);
    source=httpRequest({host:'127.0.0.1',port,path:'/api/rtcm/CAPLOC',method:'POST',
      headers:{...sourceAuth,'Content-Type':'application/octet-stream'}});
    source.flushHeaders();
    await new Promise(resolve=>setTimeout(resolve,30));
    const valid=frame([0x43,0x50,0x01]);
    const bad=Buffer.from(valid);bad[4]^=1;
    source.write(Buffer.concat([bad,valid.subarray(0,4)]));source.write(valid.subarray(4));
    let state;
    for(let i=0;i<30;i++) {
      state=await (await fetch(base+'/api/rtcm/CAPLOC/status',{headers:roverAuth})).json();
      if(state.frames===1)break;
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    assert.equal(state.frames,1);assert.equal(state.bytes,valid.length);
    assert.equal((await fetch(base+'/api/rtcm/CAPLOC/source-status',{headers:auth})).status,409);
    const sourceState=await (await fetch(base+'/api/rtcm/CAPLOC/source-status',{headers:sourceAuth})).json();
    assert.equal(sourceState.sourceConnected,true);
    assert.equal(sourceState.frames,1);
    assert.equal(sourceState.bytes,valid.length);
    const competing=await fetch(base+'/api/rtcm/CAPLOC',{method:'POST',headers:auth,body:valid});
    assert.equal(competing.status,409);
    const rover=await fetch(base+'/api/rtcm/CAPLOC',{
      headers:{Authorization:'Basic '+Buffer.from('rover:'+roverToken).toString('base64')}});
    assert.equal(rover.status,200);
    const reader=rover.body.getReader(),next=reader.read();
    source.write(valid);
    const received=await next;
    assert.deepEqual(Buffer.from(received.value),valid);
    await reader.cancel();
    source.end();
  } finally {source?.destroy();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
