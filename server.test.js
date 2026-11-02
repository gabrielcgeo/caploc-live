import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {scryptSync,createHash} from 'node:crypto';

test('private live session, upload and public viewer',async()=>{
  const data=await mkdtemp(join(tmpdir(),'caploc-live-'));
  const port=32000+Math.floor(Math.random()*10000);
  const admin='test-admin-secret-with-at-least-thirty-two-characters';
  const monitorPassword='test-monitor-password',salt='test-monitor-salt';
  const child=spawn(process.execPath,['server.js'],{
    cwd:import.meta.dirname,env:{...process.env,DATA_DIR:data,PORT:String(port),
      PUBLIC_BASE_URL:'https://explorer.example.test',EXPLORER_ADMIN_TOKEN:admin,
      MONITOR_ADMIN_EMAIL:'admin@example.test',
      MONITOR_ADMIN_PASSWORD_SCRYPT:salt+':'+scryptSync(monitorPassword+':'+admin,salt,32).toString('hex')},stdio:'ignore'});
  const base=`http://127.0.0.1:${port}`;
  try {
    let ready=false;
    for(let i=0;i<50;i++) {
      try { if((await fetch(base+'/health')).ok) {ready=true;break;} } catch { }
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    assert.ok(ready,'server started');
    assert.equal((await fetch(base+'/api/nearby-care')).status,400);
    const unauthorized=await fetch(base+'/api/sessions',{method:'POST',body:'{}'});
    assert.equal(unauthorized.status,401);
    const automatic=await fetch(base+'/api/public-sessions',{method:'POST',
      body:JSON.stringify({name:'Teste automático',ttlHours:12,monitoringEnabled:true})});
    assert.equal(automatic.status,201);
    assert.equal((await automatic.json()).id.length,43);
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
    assert.equal(viewerHtml.includes('__SESSION_ID__'),false);
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
    assert.equal((await fetch(base+'/api/monitor/sessions')).status,401);
    const badLogin=await fetch(base+'/api/monitor/login',{method:'POST',body:JSON.stringify({
      email:'admin@example.test',password:'wrong'})});
    assert.equal(badLogin.status,401);
    const login=await fetch(base+'/api/monitor/login',{method:'POST',body:JSON.stringify({
      email:'admin@example.test',password:monitorPassword})});
    assert.equal(login.status,200);
    const cookie=login.headers.get('set-cookie').split(';')[0],authorized={Cookie:cookie};
    const initial=await fetch(base+'/api/monitor/sessions',{headers:authorized});
    assert.equal(initial.status,200);
    assert.equal((await initial.json()).length,0,'anonymous sessions do not enter central');
    const codeResponse=await fetch(base+'/api/monitor/enroll-codes',{method:'POST',headers:authorized});
    assert.equal(codeResponse.status,201);
    const enrollment=await codeResponse.json(),code=enrollment.code;
    assert.ok(enrollment.expiresAt-Date.now()>119*60*1000,'QR stays valid for two hours');
    const codeFile=join(data,'enroll-'+createHash('sha256').update(code).digest('hex')+'.json');
    const encryptedCode=await disk(codeFile,'utf8');
    assert.ok(!encryptedCode.includes(code),'persistent QR record does not expose enrollment code');
    assert.match(enrollment.qr,/^data:image\/png;base64,/);
    assert.ok(Buffer.from(enrollment.qr.split(',')[1],'base64').subarray(0,8)
      .equals(Buffer.from([137,80,78,71,13,10,26,10])),'QR is a PNG generated on the server');
    const enrolled=await fetch(base+'/api/fleet/enroll',{method:'POST',body:JSON.stringify({
      code,name:'Equipe de teste'})});
    assert.equal(enrolled.status,201);
    const device=await enrolled.json();
    const profile={responsibleName:'Maria Silva',mission:'Levantamento de campo',
      phone:'31999990000',email:'maria@example.test',emergencyName:'João Silva',
      emergencyPhone:'31999991111',birthDate:'1990-04-05',cpf:'52998224725'};
    const invalidProfile=await fetch(base+'/api/fleet/enroll',{method:'POST',body:JSON.stringify({
      code,name:'Cadastro inválido',profile:{...profile,cpf:'00000000000'}})});
    assert.equal(invalidProfile.status,400,'invalid CPF rejected');
    const another=await fetch(base+'/api/fleet/enroll',{method:'POST',body:JSON.stringify({
      code,name:'Outro aparelho',profile})});
    assert.equal(another.status,201,'QR enrollment code supports multiple devices');
    const secondDevice=await another.json();
    assert.notEqual(secondDevice.deviceToken,device.deviceToken,'each device gets a separate credential');
    assert.equal(secondDevice.profileComplete,true);
    const storedProfile=await fetch(base+'/api/fleet/'+secondDevice.id+'/profile',{
      headers:{Authorization:'Bearer '+secondDevice.deviceToken}});
    assert.equal((await storedProfile.json()).profile.cpf,profile.cpf);
    const updatedProfile=await fetch(base+'/api/fleet/'+device.id+'/profile',{
      method:'PUT',headers:{Authorization:'Bearer '+device.deviceToken},
      body:JSON.stringify({name:'Equipe de teste',profile})});
    assert.equal(updatedProfile.status,200,'older device can complete registration');
    const point=await fetch(base+'/api/fleet/'+device.id+'/position',{method:'PUT',
      headers:{Authorization:'Bearer '+device.deviceToken},body:JSON.stringify({lat:-19.9,lon:-43.9,accuracy:4})});
    assert.equal(point.status,200);
    const fleet=await fetch(base+'/api/monitor/sessions',{headers:authorized});
    const fleetItems=await fleet.json();
    assert.equal(fleetItems.length,2);
    assert.ok(fleetItems.some(item=>item.name==='Equipe de teste'));
    assert.ok(fleetItems.every(item=>item.profileComplete));
    const incident=await fetch(base+'/api/fleet/'+device.id+'/incidents',{method:'POST',
      headers:{Authorization:'Bearer '+device.deviceToken},body:JSON.stringify({
        message:'Acidente de teste',mime:'image/png',media:Buffer.from('fake png').toString('base64'),
        position:{lat:-19.9,lon:-43.9}})});
    assert.equal(incident.status,201);
    const incidentId=(await incident.json()).id;
    const incidents=await fetch(base+'/api/monitor/incidents',{headers:authorized});
    assert.equal((await incidents.json())[0].message,'Acidente de teste');
    assert.equal((await fetch(base+'/api/monitor/incidents')).status,401);
    const own=await fetch(base+'/api/fleet/'+device.id+'/incidents',{
      headers:{Authorization:'Bearer '+device.deviceToken}});
    assert.equal((await own.json())[0].status,'new');
    const patch=(action,values={})=>fetch(base+'/api/monitor/incidents/'+incidentId,{
      method:'PATCH',headers:{...authorized,'Content-Type':'application/json'},
      body:JSON.stringify({action,...values})});
    assert.equal((await patch('acknowledge')).status,200);
    assert.equal((await patch('start')).status,200);
    assert.equal((await patch('priority',{priority:'critical'})).status,200);
    assert.equal((await patch('assign',{text:'Equipe de plantão'})).status,200);
    assert.equal((await patch('due',{dueAt:Date.now()+3600000})).status,200);
    assert.equal((await patch('note',{text:'Nota interna de teste'})).status,200);
    assert.equal((await patch('reply',{text:'Estamos a caminho'})).status,200);
    const fieldMessage=await fetch(base+'/api/fleet/'+device.id+'/incidents/'+incidentId+'/messages',{
      method:'POST',headers:{Authorization:'Bearer '+device.deviceToken},
      body:JSON.stringify({message:'Equipe aguarda no local'})});
    assert.equal(fieldMessage.status,200);
    const otherMessage=await fetch(base+'/api/fleet/'+secondDevice.id+'/incidents/'+incidentId+'/messages',{
      method:'POST',headers:{Authorization:'Bearer '+secondDevice.deviceToken},
      body:JSON.stringify({message:'Não pertence a mim'})});
    assert.equal(otherMessage.status,404,'another device cannot update incident');
    const ownUpdated=await fetch(base+'/api/fleet/'+device.id+'/incidents',{
      headers:{Authorization:'Bearer '+device.deviceToken}});
    const ownRecord=(await ownUpdated.json())[0];
    assert.equal(ownRecord.priority,'critical');
    assert.ok(ownRecord.timeline.some(item=>item.text==='Estamos a caminho'));
    assert.ok(!ownRecord.timeline.some(item=>item.text==='Nota interna de teste'));
    assert.equal((await patch('resolve',{text:'Atendimento concluído com segurança'})).status,200);
    assert.equal((await patch('reply',{text:'Mensagem tardia'})).status,409);
    assert.equal((await patch('close')).status,200);
    assert.equal((await patch('reopen')).status,200);
    assert.equal((await patch('resolve',{text:'Encerramento definitivo'})).status,200);
    assert.equal((await patch('close')).status,200);
    const media=await fetch(base+'/api/monitor/incidents/'+incidentId+'/media',{headers:authorized});
    assert.equal(await media.text(),'fake png');
    assert.equal((await fetch(base+'/api/monitor/incidents/'+incidentId+'/media')).status,401);
    const diskIncident=await disk(join(data,'incident-'+incidentId+'.json'),'utf8');
    assert.ok(!diskIncident.includes('Acidente de teste'),'incident encrypted at rest');
    const diskDevice=await disk(join(data,'fleet-'+device.id+'.json'),'utf8');
    assert.ok(!diskDevice.includes(profile.cpf),'personal registration encrypted at rest');
    const detail=await fetch(base+'/api/monitor/sessions/'+device.id,{headers:authorized});
    const detailRecord=await detail.json();
    assert.equal(detailRecord.points.length,1);
    assert.equal(detailRecord.profile.cpf,profile.cpf);
    const revoke=await fetch(base+'/api/monitor/fleet/'+device.id,{method:'DELETE',headers:authorized});
    assert.equal(revoke.status,200);
    assert.equal((await fetch(base+'/api/fleet/'+device.id+'/position',{method:'PUT',
      headers:{Authorization:'Bearer '+device.deviceToken},body:JSON.stringify({lat:-19.9,lon:-43.9,accuracy:4})})).status,409);
  } finally {child.kill();await rm(data,{recursive:true,force:true});}
});
