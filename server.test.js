import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

test('private live session, upload and public viewer',async()=>{
  const data=await mkdtemp(join(tmpdir(),'caploc-live-'));
  const port=32000+Math.floor(Math.random()*10000);
  const admin='test-admin-secret-with-at-least-thirty-two-characters';
  const child=spawn(process.execPath,['server.js'],{
    cwd:import.meta.dirname,env:{...process.env,DATA_DIR:data,PORT:String(port),
      PUBLIC_BASE_URL:'https://explorer.example.test',EXPLORER_ADMIN_TOKEN:admin},stdio:'ignore'});
  const base=`http://127.0.0.1:${port}`;
  try {
    let ready=false;
    for(let i=0;i<50;i++) {
      try { if((await fetch(base+'/health')).ok) {ready=true;break;} } catch { }
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    assert.ok(ready,'server started');
    const unauthorized=await fetch(base+'/api/sessions',{method:'POST',body:'{}'});
    assert.equal(unauthorized.status,401);
    const created=await fetch(base+'/api/sessions',{method:'POST',headers:{Authorization:'Bearer '+admin},
      body:JSON.stringify({name:'Caminho de teste',ttlHours:1})});
    assert.equal(created.status,201);
    const session=await created.json();
    assert.match(session.viewerUrl,/^https:\/\/explorer\.example\.test\/s\//);
    assert.equal(session.id.length,43);
    const privateBefore=await fetch(base+'/api/public/'+session.id);
    assert.equal(privateBefore.status,204);
    const wrong=await fetch(base+'/api/sessions/'+session.id+'/position',{method:'PUT',
      headers:{Authorization:'Bearer wrong'},body:JSON.stringify({lat:-19,lon:-43,accuracy:5})});
    assert.equal(wrong.status,401);
    const update=await fetch(base+'/api/sessions/'+session.id+'/position',{method:'PUT',
      headers:{Authorization:'Bearer '+session.uploadToken},body:JSON.stringify({lat:-19,lon:-43,accuracy:5})});
    assert.equal(update.status,200);
    const shown=await fetch(base+'/api/public/'+session.id);
    assert.equal(shown.status,200);
    const state=await shown.json();
    assert.equal(state.position.lat,-19);
    assert.equal(state.points.length,1);
    const page=await fetch(base+'/s/'+session.id);
    assert.equal(page.status,200);
    const viewerHtml=await page.text();
    assert.match(viewerHtml,/CapLoc · localização compartilhada/);
    assert.match(viewerHtml,/última posição conhecida/);
    assert.match(viewerHtml,/mt1\.google\.com\/vt\/lyrs=s/);
    const ended=await fetch(base+'/api/sessions/'+session.id,{method:'DELETE',
      headers:{Authorization:'Bearer '+session.uploadToken},
      body:JSON.stringify({reason:'Situação controlada'})});
    assert.equal(ended.status,200);
    const after=await fetch(base+'/api/public/'+session.id);
    assert.equal(after.status,200);
    assert.equal((await after.json()).endReason,'Situação controlada');
    const endedPage=await fetch(base+'/s/'+session.id);
    assert.equal(endedPage.status,200);
    const disk=(await import('node:fs/promises')).readFile;
    const saved=await disk(join(data,session.id+'.json'),'utf8');
    assert.ok(!saved.includes('"lat":-19'),'position encrypted at rest');
  } finally {child.kill();await rm(data,{recursive:true,force:true});}
});
