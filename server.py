import os,json,sqlite3,hashlib,hmac,secrets,datetime,threading
from http.server import ThreadingHTTPServer,SimpleHTTPRequestHandler
from urllib.parse import urlparse
from pathlib import Path
ROOT=Path(__file__).resolve().parent; DB=ROOT/'clinic.sqlite3'; LOCK=threading.Lock()
def db():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;return c
def pw(s,salt):return hashlib.pbkdf2_hmac('sha256',s.encode(),bytes.fromhex(salt),260000).hex()
def init():
 with db() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE, salt TEXT,hash TEXT,role TEXT,display TEXT);CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER,expires TEXT);CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY,owner INTEGER,kind TEXT,body TEXT,updated TEXT);CREATE TABLE IF NOT EXISTS assignments(id INTEGER PRIMARY KEY,title TEXT,kind TEXT,instructions TEXT,due TEXT);CREATE TABLE IF NOT EXISTS reviews(record_id INTEGER PRIMARY KEY,score INTEGER,feedback TEXT,reviewer INTEGER,updated TEXT);''')
  if not c.execute('select 1 from users').fetchone():
   salt=secrets.token_hex(16); password=os.environ.get('MCC_ADMIN_PASSWORD') or secrets.token_urlsafe(12)
   c.execute('insert into users(username,salt,hash,role,display) values(?,?,?,?,?)',('teacher',salt,pw(password,salt),'teacher','Окутуучу'))
   print('\n=== БИРИНЧИ КИРҮҮ ===\nЛогин: teacher\nСырсөз:',password,'\nСырсөздү коопсуз жерде сактаңыз!\n',flush=True)
class H(SimpleHTTPRequestHandler):
 def __init__(self,*a,**kw):super().__init__(*a,directory=str(ROOT),**kw)
 def sendj(self,x,status=200,cookie=None):
  b=json.dumps(x,ensure_ascii=False).encode();self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Length',str(len(b)))
  if cookie:self.send_header('Set-Cookie',cookie)
  self.end_headers();self.wfile.write(b)
 def payload(self):
  n=int(self.headers.get('Content-Length','0'))
  if n>120000:return None
  try:return json.loads(self.rfile.read(n))
  except:return None
 def user(self):
  from http.cookies import SimpleCookie
  try:co=SimpleCookie(self.headers.get('Cookie',''));token=co['session'].value
  except:return None
  with db() as c:return c.execute('select users.id,username,role,display from sessions join users on users.id=sessions.user_id where token=? and expires>?',(token,datetime.datetime.now(datetime.timezone.utc).isoformat())).fetchone()
 def do_GET(self):
  p=urlparse(self.path).path
  if not p.startswith('/api/'):return super().do_GET()
  u=self.user()
  if p=='/api/me':return self.sendj(dict(u) if u else {})
  if not u:return self.sendj({'error':'Кирүү керек'},401)
  with db() as c:
   if p=='/api/users':
    if u['role']!='teacher':return self.sendj({'error':'Уруксат жок'},403)
    return self.sendj([dict(x) for x in c.execute('select id,username,display,role from users order by id')])
   if p=='/api/assignments':return self.sendj([dict(x) for x in c.execute('select * from assignments order by id desc')])
   if p=='/api/records':
    q='''select r.id,r.owner,r.kind,r.body,r.updated,u.display as student,v.score,v.feedback from records r join users u on u.id=r.owner left join reviews v on v.record_id=r.id'''
    rows=c.execute(q+(' order by r.id desc' if u['role']=='teacher' else ' where r.owner=? order by r.id desc'),() if u['role']=='teacher' else (u['id'],)).fetchall()
    return self.sendj([{**dict(x),'body':json.loads(x['body'])} for x in rows])
  return self.sendj({'error':'Табылган жок'},404)
 def do_POST(self):
  p=urlparse(self.path).path
  if not p.startswith('/api/'):return self.sendj({'error':'Табылган жок'},404)
  origin=self.headers.get('Origin');host=self.headers.get('Host','')
  if origin and urlparse(origin).netloc!=host:return self.sendj({'error':'Origin четке кагылды'},403)
  d=self.payload()
  if not isinstance(d,dict):return self.sendj({'error':'Маалымат туура эмес'},400)
  if p=='/api/login':
   with db() as c:
    x=c.execute('select * from users where username=?',(str(d.get('username','')),)).fetchone()
    if not x or not hmac.compare_digest(pw(str(d.get('password','')),x['salt']),x['hash']):return self.sendj({'error':'Логин же сырсөз туура эмес'},401)
    token=secrets.token_urlsafe(36);expires=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=10)).isoformat()
    c.execute('insert into sessions values(?,?,?)',(token,x['id'],expires))
   return self.sendj({'ok':True},cookie=f'session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=36000')
  u=self.user()
  if not u:return self.sendj({'error':'Кирүү керек'},401)
  if p=='/api/logout':
   from http.cookies import SimpleCookie
   try:
    co=SimpleCookie(self.headers.get('Cookie',''));token=co['session'].value
    with db() as c:c.execute('delete from sessions where token=?',(token,))
   except:pass
   return self.sendj({'ok':True},cookie='session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0')
  if p=='/api/create-user':
   if u['role']!='teacher':return self.sendj({'error':'Уруксат жок'},403)
   username=str(d.get('username','')).strip();password=str(d.get('password',''));display=str(d.get('display','')).strip()
   if not (3<=len(username)<=40 and username.replace('_','').isalnum() and len(password)>=10 and display):return self.sendj({'error':'Логин 3–40 белги, сырсөз кеминде 10 белги, аты-жөнү керек'},400)
   salt=secrets.token_hex(16)
   try:
    with db() as c:c.execute('insert into users(username,salt,hash,role,display) values(?,?,?,?,?)',(username,salt,pw(password,salt),'student',display[:120]))
   except sqlite3.IntegrityError:return self.sendj({'error':'Логин колдонулууда'},409)
   return self.sendj({'ok':True})
  if p=='/api/assignment':
   if u['role']!='teacher':return self.sendj({'error':'Уруксат жок'},403)
   title=str(d.get('title','')).strip();kind=d.get('kind')
   if not title or kind not in ('outpatient','birth'):return self.sendj({'error':'Тапшырма туура эмес'},400)
   with db() as c:c.execute('insert into assignments(title,kind,instructions,due) values(?,?,?,?)',(title[:160],kind,str(d.get('instructions',''))[:2000],str(d.get('due',''))[:20]))
   return self.sendj({'ok':True})
  if p=='/api/record':
   kind=d.get('kind');body=d.get('body');rid=d.get('id')
   if kind not in ('outpatient','birth') or not isinstance(body,dict) or len(json.dumps(body))>50000:return self.sendj({'error':'Форма туура эмес'},400)
   if not any(str(v).strip() for v in body.values()):return self.sendj({'error':'Бош документ'},400)
   now=datetime.datetime.now(datetime.timezone.utc).isoformat()
   with db() as c:
    if rid:
     old=c.execute('select owner from records where id=?',(rid,)).fetchone()
     if not old or old['owner']!=u['id']:return self.sendj({'error':'Башка студенттин ишин өзгөртө албайсыз'},403)
     c.execute('update records set body=?,updated=? where id=?',(json.dumps(body,ensure_ascii=False),now,rid));c.execute('delete from reviews where record_id=?',(rid,))
    else:rid=c.execute('insert into records(owner,kind,body,updated) values(?,?,?,?)',(u['id'],kind,json.dumps(body,ensure_ascii=False),now)).lastrowid
   return self.sendj({'ok':True,'id':rid})
  if p=='/api/review':
   if u['role']!='teacher':return self.sendj({'error':'Уруксат жок'},403)
   try:rid=int(d.get('id'));score=int(d.get('score'))
   except:return self.sendj({'error':'Баалоо туура эмес'},400)
   if not 0<=score<=100:return self.sendj({'error':'Баа 0–100 болушу керек'},400)
   with db() as c:
    if not c.execute('select 1 from records where id=?',(rid,)).fetchone():return self.sendj({'error':'Документ жок'},404)
    c.execute('insert into reviews(record_id,score,feedback,reviewer,updated) values(?,?,?,?,?) on conflict(record_id) do update set score=excluded.score,feedback=excluded.feedback,reviewer=excluded.reviewer,updated=excluded.updated',(rid,score,str(d.get('feedback',''))[:3000],u['id'],datetime.datetime.now(datetime.timezone.utc).isoformat()))
   return self.sendj({'ok':True})
  return self.sendj({'error':'Табылган жок'},404)
if __name__=='__main__':
 init();port=int(os.environ.get('PORT','8000'));print(f'Ачуу: http://localhost:{port}',flush=True);ThreadingHTTPServer(('0.0.0.0',port),H).serve_forever()
