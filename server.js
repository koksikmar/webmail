/*
Simple Webmail server (single-file)
Features:
- User registration (username -> username@zsoiz.pl)
- Login (session)
- Inbox, Sent, Compose (stored in SQLite)
- Optional SMTP sending via environment variables. If not configured, messages are stored locally only.

How to run:
1) Install Node.js (>=18 recommended)
2) Create folder, save this file as server.js
3) npm init -y
4) npm i express sqlite3 bcryptjs express-session body-parser nodemailer connect-sqlite3
5) NODE_ENV=production SESSION_SECRET=your_secret SMTP_HOST=smtp.example.com SMTP_PORT=587 SMTP_USER=... SMTP_PASS=... node server.js

Open http://localhost:3000
*/

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs');

const APP_PORT = process.env.PORT || 3000;
const DOMAIN = 'zsoiz.pl';

// SMTP configuration
const SMTP_HOST = process.env.SMTP_HOST || null;
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : null;
const SMTP_USER = process.env.SMTP_USER || null;
const SMTP_PASS = process.env.SMTP_PASS || null;

let transporter = null;
if(SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS){
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT===465,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  console.log('SMTP configured — outgoing mails will be attempted.');
}else{
  console.log('SMTP not configured — mails will be stored locally only.');
}

// Database
const db = new sqlite3.Database('./webmail.db');
db.serialize(()=>{
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id INTEGER,
    from_email TEXT NOT NULL,
    to_email TEXT NOT NULL,
    subject TEXT,
    body TEXT,
    created_at INTEGER NOT NULL,
    sent_at INTEGER,
    sent INTEGER DEFAULT 0,
    FOREIGN KEY(from_user_id) REFERENCES users(id)
  )`);
});

// App
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended:true }));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: '.' }),
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge:1000*60*60*24 }
}));

// Auth middleware
function requireAuth(req,res,next){
  if(req.session && req.session.user) return next();
  return res.status(401).json({ error:'Unauthorized' });
}

// Serve static frontend
app.use('/static', express.static(path.join(__dirname,'public')));

// Routes
app.get('/', (req,res)=>{
  res.sendFile(path.join(__dirname,'public','index.html'));
});

// Register
app.post('/api/register', (req,res)=>{
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ error:'Missing username or password' });
  const cleanUser = String(username).trim().toLowerCase();
  if(!/^[a-z0-9._-]{3,30}$/.test(cleanUser)) return res.status(400).json({ error:'Invalid username (3-30 chars a-z0-9._-)' });

  const email = `${cleanUser}@${DOMAIN}`;
  const password_hash = bcrypt.hashSync(password,10);
  const created_at = Date.now();

  const stmt = db.prepare('INSERT INTO users (username,email,password_hash,created_at) VALUES (?,?,?,?)');
  stmt.run(cleanUser,email,password_hash,created_at,function(err){
    if(err){
      if(err.message.includes('UNIQUE')) return res.status(400).json({ error:'Username or email already exists' });
      return res.status(500).json({ error:'DB error: '+err.message });
    }
    req.session.user = { id:this.lastID, username:cleanUser, email };
    return res.json({ ok:true, user:req.session.user });
  });
});

// Login
app.post('/api/login',(req,res)=>{
  const { username,password } = req.body;
  if(!username || !password) return res.status(400).json({ error:'Missing username or password' });
  const cleanUser = String(username).trim().toLowerCase();
  db.get('SELECT id,username,email,password_hash FROM users WHERE username=?',[cleanUser],(err,row)=>{
    if(err) return res.status(500).json({ error:'DB error: '+err.message });
    if(!row) return res.status(400).json({ error:'Invalid credentials' });
    if(!bcrypt.compareSync(password,row.password_hash)) return res.status(400).json({ error:'Invalid credentials' });
    req.session.user = { id:row.id, username:row.username, email:row.email };
    return res.json({ ok:true, user:req.session.user });
  });
});

// Logout
app.post('/api/logout',(req,res)=>{
  req.session.destroy(()=>{ res.json({ ok:true }); });
});

// Inbox
app.get('/api/messages/inbox', requireAuth, (req,res)=>{
  const email = req.session.user.email;
  db.all('SELECT id,from_email,subject,body,created_at,sent_at,sent FROM messages WHERE to_email=? ORDER BY created_at DESC',[email],(err,rows)=>{
    if(err) return res.status(500).json({ error:'DB error: '+err.message });
    return res.json({ ok:true, messages:rows });
  });
});

// Sent
app.get('/api/messages/sent', requireAuth, (req,res)=>{
  const userId = req.session.user.id;
  db.all('SELECT id,to_email,subject,body,created_at,sent_at,sent FROM messages WHERE from_user_id=? ORDER BY created_at DESC',[userId],(err,rows)=>{
    if(err) return res.status(500).json({ error:'DB error: '+err.message });
    return res.json({ ok:true, messages:rows });
  });
});

// Send message
app.post('/api/messages/send', requireAuth, async (req,res)=>{
  try{
    const user = req.session.user;
    const { to, subject, body } = req.body;
    if(!to || !body) return res.status(400).json({ error:'Uzupełnij pola "Do" i "Treść"' });
    const created_at = Date.now();

    const stmt = db.prepare('INSERT INTO messages (from_user_id,from_email,to_email,subject,body,created_at,sent,sent_at) VALUES (?,?,?,?,?,?,?,?)');

    if(!transporter){
      // Local only
      stmt.run(user.id,user.email,to,subject||'',body,created_at,0,null,function(err){
        if(err) return res.status(500).json({ error:'DB error: '+err.message });
        return res.json({ ok:true, stored:true, messageId:this.lastID });
      });
      return;
    }

    try{
      const info = await transporter.sendMail({ from:user.email, to:to, subject:subject||'(brak tematu)', text:body });
      const sent_at = Date.now();
      stmt.run(user.id,user.email,to,subject||'',body,created_at,1,sent_at,function(err){
        if(err) return res.status(500).json({ error:'DB error after send: '+err.message });
        return res.json({ ok:true, sent:true, info, messageId:this.lastID });
      });
    }catch(err){
      console.error('SMTP send error', err);
      stmt.run(user.id,user.email,to,subject||'',body,created_at,0,null,function(e){
        if(e) return res.status(500).json({ error:'DB error: '+e.message });
        return res.status(500).json({ ok:false, error:'SMTP failed, message stored locally' });
      });
    }
  }catch(err){
    console.error('Unexpected error in /api/messages/send', err);
    return res.status(500).json({ error:'Unexpected server error: '+err.message });
  }
});

// Current user
app.get('/api/me',(req,res)=>{
  if(req.session && req.session.user) return res.json({ logged:true, user:req.session.user });
  return res.json({ logged:false });
});

// Minimal frontend auto-create if missing
const publicDir = path.join(__dirname,'public');
if(!fs.existsSync(publicDir)) fs.mkdirSync(publicDir);

const indexHtml = `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Webmail zsoiz.pl</title></head>
<body>
<h2>Webmail — zsoiz.pl (demo)</h2>
<p>Frontend w folderze public/app.js</p>
</body>
</html>`;

if(!fs.existsSync(path.join(publicDir,'index.html'))) fs.writeFileSync(path.join(publicDir,'index.html'),indexHtml);
if(!fs.existsSync(path.join(publicDir,'app.js'))) fs.writeFileSync(path.join(publicDir,'app.js'), '// tutaj wklej swój frontend JS');

app.listen(APP_PORT,()=>{ console.log(`Server running on http://localhost:${APP_PORT}`); });

