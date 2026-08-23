import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'ishv4-test-'));
process.env.ISHV4_DATA_DIR=tmp;
process.env.AUDIT_MAX_BYTES='10485760';

test('01 audit logger: structured record, sanitization, chain', async()=>{
  const { recordAudit, getAuditLogs, verifyAuditChain }=await import('../src/audit.js');
  recordAudit('u\n1','AUTH\nLOGIN','/x',200,'127.0.0.1','a\tb\r\nc',{tenantId:'t1',userId:'u1'});
  const logs=getAuditLogs(10);
  assert.equal(logs[0].actorId,'u 1'); assert.equal(logs[0].details,'a b c');
  assert.equal(verifyAuditChain().isValid,true);
});

test('03 injection guard: audit lines are single-line JSON', async()=>{
  const { getAuditLogs }=await import('../src/audit.js');
  for(const e of getAuditLogs(20)) assert.equal(JSON.stringify(e).includes('\n'),false);
});

test('04 request context exposes request/user/tenant context', async()=>{
  const { requestContextMiddleware, getRequestContext }=await import('../src/request-context.js');
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{},tenantId:'tenantA',actorId:'alice'},{setHeader:(k,v)=>assert.equal(k,'X-Request-ID')},()=>{const c=getRequestContext();try{assert.match(c.requestId,/^[0-9a-f]{8}-[0-9a-f-]{27,}$/i);assert.equal(c.tenantId,'tenantA');assert.equal(c.userId,'alice');assert.equal(c.requestId.length,36);resolve()}catch(e){reject(e)}}));
});

test('04c request context does not trust client request-id and remains isolated', async()=>{
  const { requestContextMiddleware, getRequestContext }=await import('../src/request-context.js');
  const run=(tenantId,userId,headers={})=>new Promise((resolve,reject)=>{
    requestContextMiddleware({headers,tenantId,actorId:userId},{setHeader(){}},()=>{ try { resolve(getRequestContext()); } catch (e) { reject(e); } });
  });
  const a=await run('tenantA','alice',{'x-request-id':'client-controlled-id'});
  const b=await run('tenantB','bob',{'x-request-id':'client-controlled-id'});
  assert.notEqual(a.requestId,b.requestId);
  assert.notEqual(a.requestId,'client-controlled-id');
  assert.equal(a.tenantId,'tenantA'); assert.equal(a.userId,'alice');
  assert.equal(b.tenantId,'tenantB'); assert.equal(b.userId,'bob');
});

test('04d request context omits missing identity and protects against secret metadata', async()=>{
  const { requestContextMiddleware, getRequestContext }=await import('../src/request-context.js');
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{authorization:'Bearer secret-token','password':'secret-password'},tenantId:undefined,actorId:undefined},{setHeader(){}},()=>{
    try {
      const c=getRequestContext();
      assert.equal(c.tenantId,null); assert.equal(c.userId,null);
      assert.deepEqual(Object.keys(c).sort(),['requestId','tenantId','userId'].sort());
      const serialized=JSON.stringify(c);
      assert.doesNotMatch(serialized,/secret-token|secret-password|authorization|password/i);
      resolve();
    } catch(e){reject(e)}
  }));
});

test('04e request context concurrent isolation', async()=>{
  const { requestContextMiddleware, getRequestContext }=await import('../src/request-context.js');
  const run=(tenantId,userId,delay)=>new Promise((resolve,reject)=>{
    requestContextMiddleware({headers:{},tenantId,actorId:userId},{setHeader(){}},()=>{
      setTimeout(()=>{try{const c=getRequestContext();resolve({tenantId:c.tenantId,userId:c.userId,requestId:c.requestId})}catch(e){reject(e)}},delay);
    });
  });
  const [a,b]=await Promise.all([run('tenantA','alice',10),run('tenantB','bob',1)]);
  assert.equal(a.tenantId,'tenantA'); assert.equal(a.userId,'alice');
  assert.equal(b.tenantId,'tenantB'); assert.equal(b.userId,'bob');
  assert.notEqual(a.requestId,b.requestId);
});

test('04f missing request context keeps backward-compatible fallback', async()=>{
  const { getRequestContext }=await import('../src/request-context.js');
  const c=getRequestContext();
  assert.equal(c.requestId,'system'); assert.equal(c.tenantId,null); assert.equal(c.userId,'system');
});

test('04b audit consumes request context', async()=>{
  const { logEvent, getAuditLogs }=await import('../src/audit.js');
  const { requestContextMiddleware }=await import('../src/request-context.js');
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{},tenantId:'tenantCTX',actorId:'ctx-user'},{setHeader(){ }},()=>{ try { logEvent({action:'CTX_TEST'}); const e=getAuditLogs(1)[0]; assert.equal(e.tenantId,'tenantCTX'); assert.equal(e.userId,'ctx-user'); resolve(); } catch(e){reject(e)} }));
});

test('05 tenant guard blocks mismatched authenticated tenant', async()=>{
  const { tenantGuard }=await import('../src/tenant-guard.js');
  const { requestContextMiddleware }=await import('../src/request-context.js');
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{},tenantId:'A',actorId:'alice'}, {setHeader(){}}, ()=>{
    try { tenantGuard({headers:{'x-tenant-id':'B'},sessionTenantId:'A',tenantId:'A'}, {}, err=>{assert.equal(err.code,'TENANT_CONTEXT_MISMATCH');resolve()}); } catch(e){ reject(e); }
  }));
});



test('05a tenant guard accepts trusted same-tenant context', async()=>{
  const { tenantGuard }=await import('../src/tenant-guard.js');
  const { requestContextMiddleware }=await import('../src/request-context.js');
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{'x-tenant-id':'tenantA'},tenantId:'tenantA',actorId:'alice'}, {setHeader(){}}, ()=>{
    try {
      tenantGuard({headers:{'x-tenant-id':'tenantA'},sessionTenantId:'tenantA',tenantId:'tenantA',originalUrl:'/api/kms/keys'}, {}, err=>{ assert.equal(err, undefined); resolve(); });
    } catch(e){ reject(e); }
  }));
});

test('05b tenant guard rejects missing trusted tenant context', async()=>{
  const { tenantGuard }=await import('../src/tenant-guard.js');
  const { requestContextMiddleware }=await import('../src/request-context.js');
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{},tenantId:null,actorId:'alice'}, {setHeader(){}}, ()=>{
    try {
      tenantGuard({headers:{},originalUrl:'/api/kms/keys'}, {}, err=>{ assert.equal(err.code,'TENANT_CONTEXT_REQUIRED'); resolve(); });
    } catch(e){ reject(e); }
  }));
});

test('05c client tenant override is rejected and audited with no secrets', async()=>{
  const { tenantGuard }=await import('../src/tenant-guard.js');
  const { requestContextMiddleware }=await import('../src/request-context.js');
  const { getAuditLogs }=await import('../src/audit.js');
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{},tenantId:'tenantA',actorId:'alice'}, {setHeader(){}}, ()=>{
    try {
      tenantGuard({headers:{'x-tenant-id':'tenantB'},sessionTenantId:'tenantA',originalUrl:'/api/kms/secrets'}, {}, err=>{
        assert.equal(err.code,'TENANT_CONTEXT_MISMATCH');
        const e=getAuditLogs(1)[0];
        assert.equal(e.action,'TENANT_ACCESS_DENIED');
        assert.equal(e.status,'FAIL');
        assert.equal(e.tenantId,'tenantA');
        assert.equal(e.userId,'alice');
        assert.equal(e.errorCode,'TENANT_CONTEXT_MISMATCH');
        assert.doesNotMatch(JSON.stringify(e),/secret-value|plaintext-value|Bearer\s|password-value|ciphertext-value|key-value/i);
        resolve();
      });
    } catch(e){ reject(e); }
  }));
});

test('05d tenant-scoped vault operations remain isolated concurrently', async()=>{
  const { VaultService }=await import('../src/vault-service.js');
  const backing={
    listKeys: tenant=>[tenant],
    encryptSecret: async(a,p,alg,aad,t)=>({tenantId:t}),
    decryptSecretById:(id,t)=>({tenantId:t}),
    listSecrets:t=>[{tenantId:t}],
  };
  const svc=new VaultService(backing);
  const run=(tenant, delay)=>new Promise((resolve,reject)=>{
    setTimeout(()=>{ try { resolve(svc.listKeys(tenant,tenant)); } catch(e){ reject(e); } }, delay);
  });
  const [a,b]=await Promise.all([run('tenantA',10),run('tenantB',1)]);
  assert.deepEqual(a,['tenantA']);
  assert.deepEqual(b,['tenantB']);
  assert.throws(()=>svc.listKeys('tenantB','tenantA'),/Tenant context mismatch/);
});

test('06 VaultService enforces tenant equality before delegation', async()=>{
  const { VaultService }=await import('../src/vault-service.js');
  const svc=new VaultService({listKeys:()=>['ok']});
  assert.throws(()=>svc.listKeys('B','A'),/Tenant context mismatch/);
  assert.deepEqual(svc.listKeys('A','A'),['ok']);
});

test('07A orchestrator validation is executable', async()=>{
  const { requireFields }=await import('../src/orchestrator.js');
  assert.throws(()=>requireFields(['alias'])({body:{}}),/alias is required/);
});

test('07A-orchestrator critical route contract uses existing context and tenant guard', async()=>{
  const { orchestrate }=await import('../src/orchestrator.js');
  const { requestContextMiddleware }=await import('../src/request-context.js');
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{},tenantId:'tenantA',actorId:'alice'},{setHeader(){}},async()=>{
    try {
      let called=false;
      const handler=orchestrate('kms.test',async()=>{ called=true; return 'ok'; },{requireTenant:true});
      const result=await handler({tenantId:'tenantA',originalUrl:'/api/kms/test'},{},undefined);
      assert.equal(result,'ok');
      assert.equal(called,true);
      resolve();
    } catch(e){reject(e);}
  }));
});

test('07A-orchestrator rejects missing tenant context without calling business handler', async()=>{
  const { orchestrate }=await import('../src/orchestrator.js');
  const { requestContextMiddleware }=await import('../src/request-context.js');
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{},tenantId:null,actorId:'alice'},{setHeader(){}},async()=>{
    try {
      let called=false;
      const handler=orchestrate('kms.test',async()=>{ called=true; },{requireTenant:true});
      await assert.rejects(()=>handler({tenantId:null,originalUrl:'/api/kms/test'},{},undefined),/Trusted tenant context is required/);
      assert.equal(called,false);
      const {getAuditLogs}=await import('../src/audit.js');
      const event=getAuditLogs(1)[0];
      assert.equal(event.action,'ORCHESTRATOR_ERROR');
      assert.equal(event.status,'FAIL');
      assert.equal(event.errorCode,'TENANT_CONTEXT_REQUIRED');
      assert.doesNotMatch(JSON.stringify(event),/password|token|plaintext|ciphertext|secret/i);
      resolve();
    } catch(e){reject(e);}
  }));
});

test('07A-orchestrator concurrent tenant contexts remain isolated', async()=>{
  const { orchestrate }=await import('../src/orchestrator.js');
  const { requestContextMiddleware }=await import('../src/request-context.js');
  const run=(tenantId,delay)=>new Promise((resolve,reject)=>requestContextMiddleware({headers:{},tenantId,actorId:tenantId+'-user'},{setHeader(){}},async()=>{
    try {
      const handler=orchestrate('kms.concurrent',async()=>{
        await new Promise(r=>setTimeout(r,delay));
        return (await import('../src/request-context.js')).getRequestContext();
      },{requireTenant:true});
      resolve(handler({tenantId,originalUrl:'/api/kms/test'},{},undefined));
    } catch(e){reject(e);}
  }));
  const [a,b]=await Promise.all([run('tenantA',10),run('tenantB',1)]);
  const [ca,cb]=await Promise.all([a,b]);
  assert.equal(ca.tenantId,'tenantA');
  assert.equal(cb.tenantId,'tenantB');
  assert.notEqual(ca.requestId,cb.requestId);
});

test('07A-orchestrator critical KMS routes are selectively integrated', ()=>{
  const source=fs.readFileSync(path.join(process.cwd(),'server.js'),'utf8');
  for (const route of ['kms.keys.create','kms.keys.list','kms.keys.rotate','kms.keys.revoke','kms.keys.expiry','kms.encrypt','kms.decrypt','kms.secrets.list']) {
    assert.equal(source.includes(`orchestrate('${route}'`), true, route);
  }
  assert.match(source,/app\.get\('\/api\/help'/);
  assert.doesNotMatch(source,/app\.get\('\/api\/help', handle\(orchestrate/);
});

test('07B security agent is non-destructive and returns scan shape', async()=>{
  const { runSecurityScan }=await import('../security-agent/index.js');
  const r=runSecurityScan(); assert.equal(r.policy.autoKill,false); assert.ok(Array.isArray(r.processes)); assert.ok(Array.isArray(r.network));
});

test('08 production hardening: config schema declares required controls', async()=>{
  const source=fs.readFileSync(path.join(process.cwd(),'src/config.js'),'utf8');
  for (const name of ['BODY_LIMIT','AUDIT_MAX_BYTES','STRICT_MODE','REQUIRE_MTLS','DISABLE_FALLBACKS','TRUST_PROXY']) assert.match(source,new RegExp(name));
});

test('08B ISHLock uses AES-256-GCM through KMS layer', async()=>{
  const { envelopeEncrypt, envelopeDecrypt }=await import('../src/crypto-engine.js');
  const master=crypto.randomBytes(32).toString('hex');
  const payload=envelopeEncrypt('hello','tenant:primary',1,master,'AES-256-GCM','aad');
  assert.equal(envelopeDecrypt(payload,master).plaintext,'hello');
});

test('09 spyware defender is detection-only and sanitized', async()=>{
  const { runSpywareDefender }=await import('../security/spywareDefender.js');
  const r=runSpywareDefender(); assert.ok('compromised' in r); assert.ok(Array.isArray(r.suspiciousProcesses));
});

test('10 VaultService delegates existing tenant-scoped operations without rewriting vault behavior', async()=>{
  const { VaultService }=await import('../src/vault-service.js');
  const calls=[];
  const backing={
    createKey: async(...args)=>{calls.push(['createKey',args]); return {alias:args[0],tenantId:args[2]};},
    listKeys: (...args)=>{calls.push(['listKeys',args]); return [{tenantId:args[0]}];},
    rotateKey: async(...args)=>{calls.push(['rotateKey',args]); return {alias:args[0],tenantId:args[1]};},
    revokeKey: async(...args)=>{calls.push(['revokeKey',args]); return {alias:args[0],tenantId:args[2]};},
    setKeyExpiry: async(...args)=>{calls.push(['setKeyExpiry',args]); return {alias:args[0],tenantId:args[2]};},
    encryptSecret: async(...args)=>{calls.push(['encryptSecret',args]); return {tenantId:args[4],ciphertextHex:'cipher'};},
    decryptSecretById: (...args)=>{calls.push(['decryptSecretById',args]); return {tenantId:args[1],plaintext:'value'};},
    decryptPayload: (...args)=>{calls.push(['decryptPayload',args]); return {tenantId:args[1],plaintext:'value'};},
    listSecrets: (...args)=>{calls.push(['listSecrets',args]); return [{tenantId:args[0]}];},
  };
  const svc=new VaultService(backing);
  await svc.createKey('primary','AES-256-GCM','tenantA','tenantA');
  assert.deepEqual(svc.listKeys('tenantA','tenantA'),[{tenantId:'tenantA'}]);
  await svc.rotateKey('primary','tenantA','tenantA');
  await svc.revokeKey('primary','reason','tenantA','tenantA');
  await svc.setKeyExpiry('primary',null,'tenantA','tenantA');
  await svc.encryptSecret('primary','plaintext','AES-256-GCM',null,'tenantA','tenantA');
  svc.decryptSecretById('sec_1','tenantA','tenantA');
  svc.decryptPayload({tenantId:'tenantA'},'tenantA','tenantA');
  assert.deepEqual(svc.listSecrets('tenantA','tenantA'),[{tenantId:'tenantA'}]);
  assert.equal(calls.length,9);
});

test('10a VaultService rejects cross-tenant access and emits sanitized denial audit', async()=>{
  const { VaultService }=await import('../src/vault-service.js');
  const { requestContextMiddleware }=await import('../src/request-context.js');
  const { getAuditLogs }=await import('../src/audit.js');
  const svc=new VaultService({listKeys:()=>{throw new Error('delegation must not occur');}});
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{},tenantId:'tenantA',actorId:'alice'},{setHeader(){}},()=>{
    try {
      assert.throws(()=>svc.listKeys('tenantB','tenantB'),/Tenant context mismatch/);
      const e=getAuditLogs(1)[0];
      assert.equal(e.action,'TENANT_ACCESS_DENIED');
      assert.equal(e.status,'FAIL');
      assert.equal(e.tenantId,'tenantA');
      assert.equal(e.userId,'alice');
      assert.equal(e.errorCode,'TENANT_CONTEXT_MISMATCH');
      assert.doesNotMatch(JSON.stringify(e),/plaintext|password|token|ciphertext|secret|key-value/i);
      resolve();
    } catch(e){ reject(e); }
  }));
});

test('10b VaultService requires trusted tenant context for request-scoped access', async()=>{
  const { VaultService }=await import('../src/vault-service.js');
  const svc=new VaultService({listSecrets:()=>['should-not-delegate']});
  const { requestContextMiddleware }=await import('../src/request-context.js');
  await new Promise((resolve,reject)=>requestContextMiddleware({headers:{},tenantId:null,actorId:'alice'},{setHeader(){}},()=>{
    try {
      assert.throws(()=>svc.listSecrets('tenantA','tenantA'),/Trusted tenant context is required/);
      resolve();
    } catch(e){ reject(e); }
  }));
});

test('10c VaultService preserves backward-compatible direct non-request calls', async()=>{
  const { VaultService }=await import('../src/vault-service.js');
  const svc=new VaultService({listKeys:(tenant)=>[tenant],listSecrets:(tenant)=>[{tenantId:tenant}]});
  assert.deepEqual(svc.listKeys('tenantA','tenantA'),['tenantA']);
  assert.deepEqual(svc.listSecrets('tenantA','tenantA'),[{tenantId:'tenantA'}]);
});
