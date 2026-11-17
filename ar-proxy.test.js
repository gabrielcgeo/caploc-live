import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

test('AR proxy forwards binary uploads and authenticated results',async()=>{
  const data=await mkdtemp(join(tmpdir(),'caploc-ar-proxy-'));
  const worker=createServer((request,response)=>{
    if(request.headers.authorization!=='Bearer test-private-key'){
      response.writeHead(401);response.end();return;
    }
    if(request.method==='POST'&&request.url==='/jobs'){
      let size=0;request.on('data',part=>size+=part.length);
      request.on('end',()=>{response.writeHead(202,{'content-type':'application/json'});
        response.end(JSON.stringify({id:'abc',bytes:size}));});return;
    }
    response.writeHead(200,{'content-type':'application/octet-stream'});
    response.end(Buffer.from([1,2,3,4]));
  });
  await new Promise(resolve=>worker.listen(0,'127.0.0.1',resolve));
  const port=34000+Math.floor(Math.random()*15000);
  const child=spawn(process.execPath,['server.js'],{cwd:import.meta.dirname,
    env:{...process.env,PORT:String(port),DATA_DIR:data,PUBLIC_BASE_URL:'https://caploc.example.test',
      EXPLORER_ADMIN_TOKEN:'test-admin-secret-with-at-least-thirty-two-characters',
      AR_WORKER_ORIGIN:`http://127.0.0.1:${worker.address().port}`},stdio:'ignore'});
  const base=`http://127.0.0.1:${port}`;
  try{
    let ready=false;for(let i=0;i<50;i++){
      try{if((await fetch(base+'/health')).ok){ready=true;break;}}catch{}
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    assert.ok(ready);
    const body=Buffer.alloc(2048,7);
    const upload=await fetch(base+'/api/ar/jobs',{method:'POST',
      headers:{Authorization:'Bearer test-private-key','Content-Type':'application/zip'},body});
    assert.equal(upload.status,202);assert.equal((await upload.json()).bytes,body.length);
    const result=await fetch(base+'/api/ar/jobs/abc/result',
      {headers:{Authorization:'Bearer test-private-key'}});
    assert.equal(result.status,200);
    assert.deepEqual(Buffer.from(await result.arrayBuffer()),Buffer.from([1,2,3,4]));
    assert.equal((await fetch(base+'/api/ar/jobs/abc')).status,401);
  }finally{child.kill();worker.close();await rm(data,{recursive:true,force:true});}
});
