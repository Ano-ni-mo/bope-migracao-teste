import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getFirestore, FieldValue } from 'firebase-admin/firestore';
import { getAuth } from 'firebase-admin/auth';
import { randomBytes, scrypt as scryptCb, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(scryptCb);
const PROJECT = 'bope-1ccf7';
const USERS = 'bope_users';
const CONFIG = 'bope_private/site_config';
const ORIGIN = process.env.BOPE_ALLOWED_ORIGIN || 'https://regulamento-bope.netlify.app';
const headers = { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Headers':'Content-Type, Authorization', 'Access-Control-Allow-Methods':'POST, OPTIONS', 'Vary':'Origin' };
const response = (statusCode, body) => ({ statusCode, headers, body: JSON.stringify(body) });
const norm = s => String(s ?? '').trim().toLocaleLowerCase('pt-BR');
function app() {
  if (getApps().length) return getApps()[0];
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON não configurada');
  const key = JSON.parse(raw);
  if (key.project_id !== PROJECT) throw new Error('A credencial não pertence ao projeto esperado');
  return initializeApp({ credential: cert(key), projectId: PROJECT });
}
async function passwordRecord(password) {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, 64);
  return { salt: salt.toString('hex'), hash: Buffer.from(key).toString('hex'), algorithm: 'scrypt-v1' };
}
async function verifyPassword(password, record) {
  if (!record || record.algorithm !== 'scrypt-v1') return false;
  try {
    const expected = Buffer.from(record.hash, 'hex');
    const actual = Buffer.from(await scrypt(password, Buffer.from(record.salt, 'hex'), expected.length));
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch { return false; }
}
async function bearerUser(admin, event) {
  const h = event.headers?.authorization || event.headers?.Authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return null;
  try {
    const decoded = await getAuth(admin).verifyIdToken(token, true);
    if (decoded.bope !== true || !decoded.qra || !decoded.role) return null;
    return { uid: decoded.uid, qra: decoded.qra, role: decoded.role };
  } catch { return null; }
}
export async function handler(event) {
  if (event.httpMethod === 'OPTIONS') return { statusCode:204, headers, body:'' };
  if (event.httpMethod !== 'POST') return response(405, { error:'Método não permitido.' });
  const origin = event.headers?.origin || event.headers?.Origin;
  if (origin && origin !== ORIGIN) return response(403, { error:'Origem não autorizada.' });
  let body; try { body = JSON.parse(event.body || '{}'); } catch { return response(400, { error:'JSON inválido.' }); }
  try {
    const a = app(), db = getFirestore(a), firebaseAuth = getAuth(a);
    const action = String(body.action || '');
    if (action === 'status') {
      const users = await db.collection(USERS).limit(1).get();
      const cfg = await db.doc(CONFIG).get();
      return response(200, { configured: !users.empty, siteConfig: cfg.exists ? { logoUrl:cfg.data().logoUrl || '', loginLogoUrl:cfg.data().loginLogoUrl || '', titleOverrides:cfg.data().titleOverrides || {} } : { logoUrl:'', loginLogoUrl:'', titleOverrides:{} } });
    }
    if (action === 'bootstrap') {
      const setupKey = String(body.setupKey || '');
      const qra = String(body.qra || '').trim(), password = String(body.password || '');
      if (!process.env.BOPE_SETUP_KEY || setupKey.length < 24 || setupKey !== process.env.BOPE_SETUP_KEY) return response(403, { error:'Chave de configuração inicial inválida.' });
      if (!qra || qra.length > 100 || password.length < 12 || password.length > 1024) return response(400, { error:'Informe QRA e senha com pelo menos 12 caracteres.' });
      const users = db.collection(USERS); const existing = await users.limit(1).get();
      if (!existing.empty) return response(409, { error:'A configuração inicial já foi concluída.' });
      const docId = createHash('sha256').update(norm(qra)).digest('hex');
      const record = await passwordRecord(password);
      await users.doc(docId).create({ qra, qraNorm:norm(qra), role:'Corregedor-Geral', password:record, active:true, createdAt:FieldValue.serverTimestamp(), createdBy:'bootstrap' });
      await db.doc(CONFIG).set({ logoUrl:'', loginLogoUrl:'', titleOverrides:{}, updatedAt:FieldValue.serverTimestamp() }, { merge:true });
      return response(201, { ok:true, message:'Conta inicial criada. Agora faça login.' });
    }
    if (action === 'login') {
      const qra = String(body.qra || '').trim(), password = String(body.password || '');
      if (!qra || !password || qra.length > 100 || password.length > 1024) return response(400, { error:'Informe QRA e senha.' });
      const qraNorm = norm(qra);
      const snap = await db.collection(USERS).where('qraNorm','==',qraNorm).limit(1).get();
      if (snap.empty) return response(401, { error:'QRA ou senha incorretos.' });
      const userDoc = snap.docs[0], user = userDoc.data();
      if (user.active === false || !await verifyPassword(password, user.password)) return response(401, { error:'QRA ou senha incorretos.' });
      const uid = `bope_${createHash('sha256').update(qraNorm).digest('hex').slice(0,40)}`;
      try { await firebaseAuth.getUser(uid); } catch { await firebaseAuth.createUser({ uid, displayName:user.qra }); }
      await firebaseAuth.setCustomUserClaims(uid, { bope:true, qra:user.qra, role:user.role });
      const token = await firebaseAuth.createCustomToken(uid, { bope:true, qra:user.qra, role:user.role });
      await db.collection('artifacts').doc('pc-vademecum-system').collection('public').doc('data').collection('bope_audit_logs').add({ actor:user.qra, role:user.role, action:'Sessão iniciada', details:'Autenticação por QRA', createdAt:FieldValue.serverTimestamp() });
      return response(200, { token, user:{ username:user.qra, role:user.role } });
    }
    const actor = await bearerUser(a, event);
    if (!actor) return response(401, { error:'Sessão inválida ou expirada.' });
    // Revalida o usuário no banco a cada chamada: conta removida/inativada ou cargo alterado perde acesso imediatamente.
    const actorId = createHash('sha256').update(norm(actor.qra)).digest('hex');
    const actorSnap = await db.collection(USERS).doc(actorId).get();
    if (!actorSnap.exists || actorSnap.data().active === false || norm(actorSnap.data().qra) !== norm(actor.qra) || actorSnap.data().role !== actor.role) {
      return response(401, { error:'Esta conta foi removida, desativada ou teve o cargo alterado. Entre novamente.' });
    }
    const isCorregedoria = ['corregedoria','corregedor-geral'].includes(norm(actor.role));
    const isGeneral = norm(actor.role) === 'corregedor-geral';
    if (action === 'list-users') {
      if (!isCorregedoria) return response(403, { error:'Acesso restrito à Corregedoria.' });
      const snap = await db.collection(USERS).get();
      return response(200, { users:snap.docs.map(d => { const u=d.data(); return { id:d.id, username:u.qra, role:u.role, active:u.active !== false }; }) });
    }
    if (action === 'create-user') {
      if (!isCorregedoria) return response(403, { error:'Acesso restrito à Corregedoria.' });
      const qra=String(body.qra||'').trim(), password=String(body.password||''), role=String(body.role||'Corregedoria');
      if (!qra || qra.length>100 || password.length<8 || password.length>1024) return response(400,{error:'QRA inválido ou senha menor que 8 caracteres.'});
      if (!['Corregedoria','Corregedor-Geral'].includes(role)) return response(400,{error:'Cargo inválido.'});
      if (role==='Corregedor-Geral' && !isGeneral) return response(403,{error:'Somente o Corregedor-Geral pode atribuir esse cargo.'});
      const id=createHash('sha256').update(norm(qra)).digest('hex'), ref=db.collection(USERS).doc(id);
      if ((await ref.get()).exists) return response(409,{error:'Já existe um usuário com esse QRA.'});
      await ref.create({ qra, qraNorm:norm(qra), role, password:await passwordRecord(password), active:true, createdAt:FieldValue.serverTimestamp(), createdBy:actor.qra });
      await db.collection('artifacts').doc('pc-vademecum-system').collection('public').doc('data').collection('bope_audit_logs').add({actor:actor.qra,role:actor.role,action:'Acesso cadastrado',details:`QRA: ${qra}; perfil: ${role}`,createdAt:FieldValue.serverTimestamp()});
      return response(201,{ok:true});
    }
    if (action === 'delete-user') {
      if (!isCorregedoria) return response(403,{error:'Acesso restrito à Corregedoria.'});
      const ref=db.collection(USERS).doc(String(body.id||'')), snap=await ref.get();
      if (!snap.exists) return response(404,{error:'Usuário não encontrado.'});
      const u=snap.data(); if (norm(u.qra)===norm(actor.qra)) return response(400,{error:'Não é possível excluir a própria conta.'});
      if (u.role==='Corregedor-Geral' && !isGeneral) return response(403,{error:'Somente o Corregedor-Geral pode remover essa conta.'});
      const targetUid = `bope_${createHash('sha256').update(norm(u.qra)).digest('hex').slice(0,40)}`;
      try { await firebaseAuth.revokeRefreshTokens(targetUid); await firebaseAuth.deleteUser(targetUid); } catch (e) { if (e?.code !== 'auth/user-not-found') throw e; }
      await ref.delete(); await db.collection('artifacts').doc('pc-vademecum-system').collection('public').doc('data').collection('bope_audit_logs').add({actor:actor.qra,role:actor.role,action:'Acesso removido',details:`QRA: ${u.qra}`,createdAt:FieldValue.serverTimestamp()});
      return response(200,{ok:true});
    }
    if (action === 'change-password') {
      const targetId=String(body.id||''), password=String(body.password||'');
      if (password.length<8 || password.length>1024) return response(400,{error:'A senha deve ter pelo menos 8 caracteres.'});
      const ref=db.collection(USERS).doc(targetId), snap=await ref.get(); if (!snap.exists) return response(404,{error:'Usuário não encontrado.'});
      const target=snap.data();
      if (norm(target.qra)!==norm(actor.qra) && !isCorregedoria) return response(403,{error:'Só é permitido alterar a própria senha.'});
      await ref.update({password:await passwordRecord(password), passwordChangedAt:FieldValue.serverTimestamp()});
      await db.collection('artifacts').doc('pc-vademecum-system').collection('public').doc('data').collection('bope_audit_logs').add({actor:actor.qra,role:actor.role,action:'Senha alterada/resetada',details:`Conta afetada: ${target.qra}`,createdAt:FieldValue.serverTimestamp()});
      return response(200,{ok:true});
    }
    if (action === 'save-document') {
      if (!isCorregedoria) return response(403,{error:'Apenas a Corregedoria pode publicar ou editar o acervo.'});
      const key = String(body.key || '');
      const data = body.document;
      if (!/^[A-Za-z0-9_-]{1,120}$/.test(key)) return response(400,{error:'Identificador de documento inválido.'});
      if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.chapters)) return response(400,{error:'Estrutura do documento inválida.'});
      const serialized = JSON.stringify(data);
      if (Buffer.byteLength(serialized, 'utf8') > 850000) return response(413,{error:'Este documento é muito grande para ser salvo de uma só vez. Divida o conteúdo em capítulos menores.'});
      const title = String(data.title || '').slice(0,500);
      await db.collection('artifacts').doc('pc-vademecum-system').collection('public').doc('data').collection('pc_vademecum_docs').doc(key).set({ ...data, title, updatedAt:FieldValue.serverTimestamp() }, { merge:true });
      await db.collection('artifacts').doc('pc-vademecum-system').collection('public').doc('data').collection('bope_audit_logs').add({actor:actor.qra,role:actor.role,action:'Acervo alterado',details:`Documento/seção: ${key}`,createdAt:FieldValue.serverTimestamp()});
      return response(200,{ok:true});
    }
    if (action === 'save-site-config') {
      if (!isCorregedoria) return response(403,{error:'Acesso restrito à Corregedoria.'});
      const safe={logoUrl:String(body.logoUrl||'').slice(0,2048),loginLogoUrl:String(body.loginLogoUrl||'').slice(0,2048),titleOverrides:body.titleOverrides && typeof body.titleOverrides==='object' ? body.titleOverrides : {},updatedAt:FieldValue.serverTimestamp()};
      await db.doc(CONFIG).set(safe,{merge:true}); return response(200,{ok:true});
    }
    return response(400,{error:'Ação desconhecida.'});
  } catch (err) {
    console.error('Erro na função BOPE:', err?.message || err);
    return response(500,{error:'Erro interno. Verifique a configuração da função no Netlify.'});
  }
}
