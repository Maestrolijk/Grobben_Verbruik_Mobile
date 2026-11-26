const $ = id => document.getElementById(id);
const magic = new TextEncoder().encode('GVENC001');
export async function decryptSnapshot(bytes, password) {
  if (bytes.length < 52 || !magic.every((v,i)=>bytes[i]===v)) throw Error('Onbekend bestandsformaat.');
  const header = bytes.subarray(0,36);
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({name:'PBKDF2',salt:bytes.subarray(8,24),iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.subarray(24,36),additionalData:header,tagLength:128},key,bytes.subarray(36)));
}
async function getFile(name, type) {
  const response = await fetch('./'+name,{cache:'no-store',credentials:'same-origin'});
  if (!response.ok) throw Error('Bestand niet beschikbaar: '+name);
  return type==='json' ? response.json() : new Uint8Array(await response.arrayBuffer());
}
if (typeof document !== 'undefined') {
  $('unlock').addEventListener('submit', async event => {
    event.preventDefault();
    const password = $('password').value;
    $('password').value=''; $('submit').disabled=true;
    $('status').textContent='Gegevens ophalen en ontsleutelen…';
    try {
      if (!globalThis.crypto?.subtle) throw Error('Gebruik HTTPS of localhost.');
      const [bytes, files] = await Promise.all([getFile('verbruik.enc'), getFile('app.json','json')]);
      if (!Array.isArray(files) || files.some(f=>f.name==='data/verbruik.rds')) throw Error('Onveilige of ongeldige code-export.');
      let snapshot;
      try { snapshot=await decryptSnapshot(bytes,password); }
      catch { throw Error('Onjuist wachtwoord of beschadigd gegevensbestand.'); }
      $('status').textContent='Grobben Verbruik starten…';
      const {runApp}=await import('./shinylive/shinylive.js');
      files.push({name:'data/verbruik.rds',type:'binary',content:snapshot});
      $('root').hidden=false;
      runApp($('root'),'viewer',{startFiles:files,showHeaderBar:false},'r');
      $('gate').hidden=true; $('lock').hidden=false;
    } catch (error) {
      $('status').textContent=error.message; $('submit').disabled=false;
      $('password').focus();
    }
  });
  $('lock').addEventListener('click',()=>location.reload());
  window.addEventListener('pageshow',event=>{if(event.persisted) location.reload();});
}
