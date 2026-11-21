const express=require("express"),Database=require("better-sqlite3"),crypto=require("crypto"),fs=require("fs"),path=require("path");
const PORT=process.env.PORT||3000,PROD=process.env.NODE_ENV==="production";
const DBP=process.env.DB_PATH||path.join(__dirname,"data","prenotazioni.db");
fs.mkdirSync(path.dirname(DBP),{recursive:true});
const db=new Database(DBP);db.pragma("journal_mode=WAL");
db.exec(`CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY,name TEXT NOT NULL,code TEXT UNIQUE NOT NULL,cat TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS appts(id TEXT PRIMARY KEY,client_id TEXT NOT NULL,env INTEGER NOT NULL,date TEXT NOT NULL,start TEXT NOT NULL,dur INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS instructors(n INTEGER PRIMARY KEY,hash TEXT NOT NULL,custom INTEGER DEFAULT 0);`);
const CATS=["AM","A1","A2","A3","B","ALTRO"],ENVS=[1,2,3,4];
const hash=p=>{const s=crypto.randomBytes(16).toString("hex");return s+":"+crypto.scryptSync(p,s,32).toString("hex")};
const check=(p,h)=>{const[s,x]=h.split(":");const y=crypto.scryptSync(p,s,32).toString("hex");return crypto.timingSafeEqual(Buffer.from(x),Buffer.from(y))};
const ADMIN_PW=process.env.ADMIN_PASSWORD||"Giulietta0650";
if(!process.env.ADMIN_PASSWORD)console.warn("ATTENZIONE: ADMIN_PASSWORD non impostata, uso la password predefinita.");
const ADMIN_H=hash(ADMIN_PW);
ENVS.forEach(n=>{if(!db.prepare("SELECT 1 FROM instructors WHERE n=?").get(n))db.prepare("INSERT INTO instructors(n,hash) VALUES(?,?)").run(n,hash("Istruttore"+n))});
const SECRET=process.env.SESSION_SECRET||(console.warn("ATTENZIONE: SESSION_SECRET non impostata: dopo ogni riavvio tutti dovranno rifare l'accesso."),crypto.randomBytes(32).toString("hex"));
const sign=o=>{const b=Buffer.from(JSON.stringify(o)).toString("base64url");return b+"."+crypto.createHmac("sha256",SECRET).update(b).digest("base64url")};
const verify=t=>{try{const[b,s]=t.split(".");const e=crypto.createHmac("sha256",SECRET).update(b).digest("base64url");if(s.length!==e.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(e)))return null;const o=JSON.parse(Buffer.from(b,"base64url"));return o.exp>Date.now()?o:null}catch(e){return null}};
const cookie=(req,k)=>((req.headers.cookie||"").split(/;\s*/).find(c=>c.startsWith(k+"="))||"").slice(k.length+1);
const tries=new Map();
const app=express();app.set("trust proxy",1);
app.use((req,res,next)=>{if(PROD&&req.headers["x-forwarded-proto"]==="http")return res.redirect(301,"https://"+req.headers.host+req.url);
  res.set({"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer"});next()});
app.use(express.json({limit:"20kb"}));
app.use("/api",(req,res,next)=>{res.set("Cache-Control","no-store");if(req.method!=="GET"&&req.method!=="HEAD"&&!req.is("json"))return res.status(415).json({error:"Richiesta non valida"});next()});
const ID=/^[a-z0-9]{1,32}$/i;
const err=(res,c,m)=>res.status(c).json({error:m});
function auth(req,res,next){const s=verify(cookie(req,"sid"));if(!s)return err(res,401,"Accesso richiesto");req.s=s;next()}
const admin=(req,res,next)=>req.s.role==="admin"?next():err(res,403,"Non consentito");
const staff=(req,res,next)=>req.s.role==="client"?err(res,403,"Non consentito"):next();
const canEnv=(s,e)=>s.role==="admin"||(s.role==="staff"&&s.env===e);

app.post("/api/login",(req,res)=>{
  const ip=req.ip,t=tries.get(ip)||{n:0,t:Date.now()};if(Date.now()-t.t>9e5){t.n=0;t.t=Date.now()}
  if(t.n>=10)return err(res,429,"Troppi tentativi. Riprova tra qualche minuto.");
  const code=String(req.body.code||"").trim().slice(0,100);let s=null;
  if(code){
    if(check(code,ADMIN_H))s={role:"admin",name:"Titolare"};
    if(!s)for(const r of db.prepare("SELECT * FROM instructors").all())if(check(code,r.hash)){s={role:"staff",env:r.n,name:"Istruttore "+r.n};break}
    if(!s){const c=db.prepare("SELECT * FROM clients WHERE code=?").get(code.toUpperCase());if(c)s={role:"client",id:c.id,name:c.name}}
  }
  if(!s){t.n++;tries.set(ip,t);return err(res,401,"Codice non valido")}
  tries.delete(ip);s.exp=Date.now()+12*3600e3;
  res.cookie("sid",sign(s),{httpOnly:true,sameSite:"strict",secure:PROD,maxAge:12*3600e3,path:"/"});res.json({ok:true});
});
app.post("/api/logout",(req,res)=>{res.clearCookie("sid");res.json({ok:true})});

app.get("/api/data",auth,(req,res)=>{
  const s=req.s,me={role:s.role,name:s.name,env:s.env,id:s.id};let clients=[],appts=[],pw=[];
  if(s.role==="admin"){clients=db.prepare("SELECT id,name,code,cat FROM clients").all();appts=db.prepare("SELECT id,client_id AS clientId,env,date,start,dur FROM appts").all();
    pw=db.prepare("SELECT n AS id FROM instructors WHERE custom=1").all()}
  else if(s.role==="staff"){clients=db.prepare("SELECT id,name,cat FROM clients").all();appts=db.prepare("SELECT id,client_id AS clientId,env,date,start,dur FROM appts WHERE env=?").all(s.env)}
  else appts=db.prepare("SELECT id,client_id AS clientId,env,date,start,dur FROM appts WHERE client_id=?").all(s.id);
  res.json({me,clients,appts,pw});
});

app.put("/api/clients/:id",auth,admin,(req,res)=>{
  const id=req.params.id,name=String(req.body.name||"").trim().slice(0,80),cat=req.body.cat||"";
  if(!ID.test(id)||!name||(cat&&!CATS.includes(cat)))return err(res,400,"Dati non validi");
  if(db.prepare("SELECT 1 FROM clients WHERE id=?").get(id))db.prepare("UPDATE clients SET name=?,cat=? WHERE id=?").run(name,cat,id);
  else{const A="ABCDEFGHJKMNPQRSTUVWXYZ23456789";let c;do{c=Array.from(crypto.randomBytes(8),b=>A[b%A.length]).join("")}while(db.prepare("SELECT 1 FROM clients WHERE code=?").get(c));
    db.prepare("INSERT INTO clients(id,name,code,cat) VALUES(?,?,?,?)").run(id,name,c,cat)}
  res.json({ok:true});
});
app.delete("/api/clients/:id",auth,admin,(req,res)=>{db.prepare("DELETE FROM appts WHERE client_id=?").run(req.params.id);db.prepare("DELETE FROM clients WHERE id=?").run(req.params.id);res.json({ok:true})});

app.put("/api/appts/:id",auth,staff,(req,res)=>{
  const id=req.params.id,b=req.body,env=Number(b.env),dur=Number(b.dur);
  if(!ID.test(id)||!ENVS.includes(env)||!/^\d{4}-\d\d-\d\d$/.test(b.date)||!/^([01]\d|2[0-3]):[0-5]\d$/.test(b.start)||!Number.isInteger(dur)||dur<15||dur>480)return err(res,400,"Dati non validi");
  if(!canEnv(req.s,env))return err(res,403,"Non puoi modificare questo istruttore");
  const old=db.prepare("SELECT env FROM appts WHERE id=?").get(id);if(old&&!canEnv(req.s,old.env))return err(res,403,"Non consentito");
  if(!db.prepare("SELECT 1 FROM clients WHERE id=?").get(b.clientId))return err(res,400,"Cliente inesistente");
  const m=t=>+t.slice(0,2)*60+ +t.slice(3),s1=m(b.start);
  const clash=db.prepare("SELECT start,dur FROM appts WHERE env=? AND date=? AND id<>?").all(env,b.date,id).some(x=>m(x.start)<s1+dur&&m(x.start)+x.dur>s1);
  if(clash)return err(res,409,"Istruttore già occupato in quell'orario");
  if(old)db.prepare("UPDATE appts SET client_id=?,env=?,date=?,start=?,dur=? WHERE id=?").run(b.clientId,env,b.date,b.start,dur,id);
  else db.prepare("INSERT INTO appts(id,client_id,env,date,start,dur) VALUES(?,?,?,?,?,?)").run(id,b.clientId,env,b.date,b.start,dur);
  res.json({ok:true});
});
app.delete("/api/appts/:id",auth,staff,(req,res)=>{const o=db.prepare("SELECT env FROM appts WHERE id=?").get(req.params.id);
  if(o&&!canEnv(req.s,o.env))return err(res,403,"Non consentito");db.prepare("DELETE FROM appts WHERE id=?").run(req.params.id);res.json({ok:true})});

app.put("/api/pw/:n",auth,admin,(req,res)=>{const n=+req.params.n,p=String(req.body.password||"");
  if(!ENVS.includes(n)||p.length<6||p.length>100)return err(res,400,"La password deve avere almeno 6 caratteri");
  db.prepare("UPDATE instructors SET hash=?,custom=1 WHERE n=?").run(hash(p),n);res.json({ok:true})});

app.use(express.static(path.join(__dirname,"public")));
app.listen(PORT,()=>console.log("Prenotazioni attivo sulla porta "+PORT));
