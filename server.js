const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
app.use(express.json({ limit: '32kb' }));
app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-control-token, x-device-token');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_KEY = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const PORT = Number(process.env.PORT || 3000);
const peers = new Map();
const online = new Map();

function token(n=32) { return crypto.randomBytes(n).toString('base64url'); }
function hash(v) { return crypto.createHash('sha256').update(String(v)).digest('hex'); }
function equal(a,b) { const x=Buffer.from(String(a||'')), y=Buffer.from(String(b||'')); return x.length===y.length && crypto.timingSafeEqual(x,y); }
function fail(res, err) { console.error(err); return res.status(err.status || 500).json({error:err.message || 'Internal server error'}); }
async function db(path, options={}) {
  if (!SUPABASE_URL || !SUPABASE_KEY) { const e=new Error('Railway variables SUPABASE_URL dan SUPABASE_SECRET_KEY belum diatur'); e.status=503; throw e; }
  const r = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, { ...options, headers: { apikey:SUPABASE_KEY, Authorization:`Bearer ${SUPABASE_KEY}`, 'Content-Type':'application/json', Prefer:'return=representation', ...(options.headers||{}) } });
  const t=await r.text(); let d=null; try { d=t?JSON.parse(t):null; } catch {}
  if(!r.ok) { const e=new Error(d?.message || d?.hint || `Supabase HTTP ${r.status}`); e.status=r.status>=500?502:400; throw e; }
  return d;
}
async function get(id) { const a=await db(`flashlight_commands?device_id=eq.${encodeURIComponent(id)}&select=*`,{method:'GET'}); return a?.[0]||null; }
async function update(id, patch) { return db(`flashlight_commands?device_id=eq.${encodeURIComponent(id)}`, {method:'PATCH',body:JSON.stringify(patch)}); }
function deviceInfo(row) { const last=row.last_seen_at; return { deviceId:row.device_id, name:row.device_name || 'Android device', command:row.command || 'OFF', lastSeenAt:last, paired:!row.pairing_code_hash, online:online.has(row.device_id) || (!!last && Date.now()-new Date(last).getTime()<45000) }; }
function sendDevice(id, data) { const set=peers.get(id); if(!set) return; const msg=JSON.stringify(data); for(const ws of set) if(ws.readyState===1) ws.send(msg); }

app.get('/api/health', (req,res)=>res.status(SUPABASE_URL&&SUPABASE_KEY?200:503).json({ok:!!(SUPABASE_URL&&SUPABASE_KEY), service:'remote-flashlight-railway'}));

app.post('/api/devices', async (req,res)=>{ try {
  const name=String(req.body?.name || 'Android device').trim().slice(0,48) || 'Android device';
  const deviceId='dev_'+token(9), pairingCode=token(6).toUpperCase(), controlToken=token(32);
  await db('flashlight_commands',{method:'POST',body:JSON.stringify({device_id:deviceId,device_name:name,command:'OFF',device_token_hash:hash('pending-'+token()),control_token_hash:hash(controlToken),pairing_code_hash:hash(pairingCode),created_at:new Date().toISOString(),updated_at:new Date().toISOString()})});
  res.status(201).json({deviceId,pairingCode,controlToken,name,paired:false});
 } catch(e){fail(res,e)} });

app.get('/api/devices', async (req,res)=>{ try {
  const id=String(req.query.deviceId||''), t=String(req.headers['x-control-token']||'');
  if(!id || !t) return res.status(400).json({error:'deviceId dan x-control-token wajib diisi'});
  const row=await get(id); if(!row || !equal(row.control_token_hash,hash(t))) return res.status(401).json({error:'ID atau control token salah'});
  res.json(deviceInfo(row));
 } catch(e){fail(res,e)} });

app.post('/api/pair', async (req,res)=>{ try {
  const code=String(req.body?.pairingCode||'').trim().toUpperCase(); if(!code) return res.status(400).json({error:'pairingCode wajib diisi'});
  const rows=await db(`flashlight_commands?pairing_code_hash=eq.${encodeURIComponent(hash(code))}&select=device_id`,{method:'GET'}); const row=rows?.[0];
  if(!row) return res.status(404).json({error:'Kode pairing salah atau sudah digunakan'});
  const deviceToken=token(32); const changed=await db(`flashlight_commands?device_id=eq.${encodeURIComponent(row.device_id)}&pairing_code_hash=eq.${encodeURIComponent(hash(code))}`,{method:'PATCH',body:JSON.stringify({device_token_hash:hash(deviceToken),pairing_code_hash:null,updated_at:new Date().toISOString()})});
  if(!changed?.length) return res.status(409).json({error:'Kode sudah digunakan. Buat perangkat baru.'});
  sendDevice(row.device_id,{type:'paired'}); res.json({deviceId:row.device_id,deviceToken});
 } catch(e){fail(res,e)} });

app.post('/api/command', async (req,res)=>{ try {
  const id=String(req.body?.deviceId||''), cmd=String(req.body?.command||'').toUpperCase(), t=String(req.headers['x-control-token']||'');
  if(!id||!t||!['ON','OFF'].includes(cmd)) return res.status(400).json({error:'deviceId, control token, dan command ON/OFF wajib diisi'});
  const row=await get(id); if(!row||!equal(row.control_token_hash,hash(t))) return res.status(401).json({error:'ID atau control token salah'});
  if(row.pairing_code_hash) return res.status(409).json({error:'Perangkat belum pairing. Masukkan kode di APK terlebih dahulu.'});
  await update(id,{command:cmd,updated_at:new Date().toISOString()}); sendDevice(id,{type:'command',command:cmd}); res.json({ok:true,deviceId:id,command:cmd});
 } catch(e){fail(res,e)} });

// APK lama tetap kompatibel dengan GET /api/device dan header x-device-token.
app.get('/api/device', async (req,res)=>{ try {
  const id=String(req.query.deviceId||''), t=String(req.headers['x-device-token']||'');
  if(!id||!t) return res.status(400).json({error:'deviceId dan x-device-token wajib diisi'});
  const row=await get(id); if(!row||!equal(row.device_token_hash,hash(t))||row.pairing_code_hash) return res.status(401).json({error:'Device token salah atau belum dipasangkan'});
  const now=new Date().toISOString(); await update(id,{last_seen_at:now}); online.set(id,Date.now());
  res.json({deviceId:id,command:row.command||'OFF'});
 } catch(e){fail(res,e)} });
app.post('/api/device', async (req,res)=>{ try {
  const id=String(req.body?.deviceId||''), t=String(req.headers['x-device-token']||'');
  if(!id||!t) return res.status(400).json({error:'deviceId dan x-device-token wajib diisi'});
  const row=await get(id); if(!row||!equal(row.device_token_hash,hash(t))||row.pairing_code_hash) return res.status(401).json({error:'Device token salah atau belum dipasangkan'});
  const now=new Date().toISOString(); await update(id,{last_seen_at:now}); online.set(id,Date.now()); res.json({ok:true,deviceId:id,command:row.command||'OFF'});
 } catch(e){fail(res,e)} });

// Optional WebSocket endpoint for future clients. Current APK uses the compatible REST endpoint above.
wss.on('connection',(ws,req)=>{
  let deviceId=null;
  ws.on('message',async raw=>{ try {
    const msg=JSON.parse(String(raw));
    if(msg.type==='device-auth') {
      const id=String(msg.deviceId||''), t=String(msg.deviceToken||''); const row=await get(id);
      if(!row||row.pairing_code_hash||!equal(row.device_token_hash,hash(t))) { ws.send(JSON.stringify({type:'error',error:'Device authentication failed'})); ws.close(1008,'unauthorized'); return; }
      deviceId=id; if(!peers.has(id)) peers.set(id,new Set()); peers.get(id).add(ws); online.set(id,Date.now()); ws.send(JSON.stringify({type:'ready',command:row.command||'OFF'}));
    } else if(msg.type==='ping' && deviceId) { online.set(deviceId,Date.now()); ws.send(JSON.stringify({type:'pong'})); }
  } catch { ws.send(JSON.stringify({type:'error',error:'Invalid message'})); } });
  ws.on('close',()=>{ if(deviceId&&peers.has(deviceId)){peers.get(deviceId).delete(ws); if(!peers.get(deviceId).size) peers.delete(deviceId); if(!peers.has(deviceId)) online.delete(deviceId);} });
});

app.get('/',(req,res)=>res.type('text').send('Remote Flashlight Controller API is running.'));
server.listen(PORT,'0.0.0.0',()=>console.log(`Remote Flashlight API listening on ${PORT}`));
