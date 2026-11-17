import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {mkdtemp,rm,readdir,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {scryptSync} from 'node:crypto';

test('monitor login survives service restart and logout revokes it',async()=>{
  const data=await mkdtemp(join(tmpdir(),'caploc-monitor-session-'));
  const port=35000+Math.floor(Math.random()*5000);
  const base=`http://127.0.0.1:${port}`;
  const admin='monitor-test-secret-at-least-thirty-two-characters';
  const password='private-test-password',salt='private-test-salt';
  const env={...process.env,DATA_DIR:data,PORT:String(port),
    PUBLIC_BASE_URL:'https://explorer.example.test',EXPLORER_ADMIN_TOKEN:admin,
    MONITOR_ADMIN_EMAIL:'admin@example.test',
    MONITOR_ADMIN_PASSWORD_SCRYPT:salt+':'+scryptSync(password+':'+admin,salt,32).toString('hex')};
  let child;
  const start=async()=>{
    child=spawn(process.execPath,['server.js'],{cwd:import.meta.dirname,env,stdio:'ignore'});
    for(let i=0;i<50;i++){
      try{if((await fetch(base+'/health')).ok)return;}catch{}
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    throw new Error('monitor server did not start');
  };
  const stop=async()=>{
    if(!child)return;
    const running=child;child=null;
    await new Promise(resolve=>{running.once('exit',resolve);running.kill();});
  };
  try{
    await start();
    const login=await fetch(base+'/api/monitor/login',{method:'POST',body:JSON.stringify({
      email:'admin@example.test',password})});
    assert.equal(login.status,200);
    assert.match(login.headers.get('set-cookie'),/Max-Age=2592000/);
    const cookie=login.headers.get('set-cookie').split(';')[0];
    const headers={Cookie:cookie};
    assert.equal((await fetch(base+'/api/monitor/sessions',{headers})).status,200);
    const files=(await readdir(data)).filter(name=>name.startsWith('monitor-session-'));
    assert.equal(files.length,1);
    assert.ok(!(await readFile(join(data,files[0]),'utf8')).includes(cookie.split('=')[1]));
    await stop();await start();
    assert.equal((await fetch(base+'/api/monitor/sessions',{headers})).status,200);
    assert.equal((await fetch(base+'/api/monitor/logout',{method:'POST',headers})).status,200);
    assert.equal((await fetch(base+'/api/monitor/sessions',{headers})).status,401);
  }finally{await stop();await rm(data,{recursive:true,force:true});}
});
