const express = require('express');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const admin = require('firebase-admin');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ololu-secret-key-lumajang-2024-xK9mP';

app.use(cors());
app.use(express.json());

// Log untuk Debugging di Render
app.use((req, res, next) => {
  console.log(`>>> ${req.method} ${req.url}`);
  if (req.method === 'POST' || req.method === 'PUT') console.log('Body:', JSON.stringify(req.body));
  next();
});

// --- FUNGSI KEAMANAN ---
function checkPassword(password, stored) {
  if (!stored || !password) return false;
  if (stored.startsWith('plain:')) return password === stored.slice(6);
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const derived = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha256').toString('hex');
  return derived === hash;
}

const hashPassword = (password) => {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha256').toString('hex');
    return `${salt}:${hash}`;
};

const generateToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

// --- INITIALIZE FIREBASE ---
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('Firebase Admin Initialized');
  } catch (e) {
    console.error('Firebase Init Error:', e.message);
  }
}

const sendNotification = async (userId, payload) => {
  if (!admin.apps.length) return;
  try {
    // Get FCM token from Supabase
    const tokens = await supabase('fcm_tokens', 'GET', null, `?id=eq.${userId}`);
    const token = tokens[0]?.token;
    if (!token) return;

    const message = {
      token: token,
      notification: {
        title: payload.title,
        body: payload.body,
      },
      data: payload.data || {},
      android: {
        priority: 'high',
        notification: {
          sound: 'default',
          channelId: 'order_notifications'
        }
      }
    };
    await admin.messaging().send(message);
    console.log('Notification sent successfully to', userId);
  } catch (e) {
    console.error('Notification error:', e.message);
  }
};

// --- HELPER SUPABASE ---
const supabase = async (table, method = 'GET', body = null, query = '') => {
  const baseUrl = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const url = `${baseUrl}/rest/v1/${table}${query}`;
  const apiKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

  if (!baseUrl || !apiKey) {
    throw new Error('Konfigurasi SUPABASE_URL atau KEY belum diset!');
  }

  const headers = {
    'apikey': apiKey,
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
  };

  try {
    const res = await axios({ url, method, data: body, headers, timeout: 15000 });
    return res.data;
  } catch (e) {
    throw new Error(e.response?.data?.message || e.message);
  }
};

// --- ROUTES ---

app.get('/', (req, res) => res.send('OLOLU Backend is Running!'));

// 1. AUTH & OTP
app.post('/api/auth/kirim-otp', async (req, res) => {
  const { nomor_hp } = req.body;
  const hp = nomor_hp.replace(/\D/g, '').replace(/^0/, '62');
  const kode = Math.floor(100000 + Math.random() * 900000).toString();
  const expires_at = new Date(Date.now() + 5 * 60000).toISOString();
  try {
    await supabase('otp', 'POST', { hp, kode, expires_at });
    const token = process.env.FONNTE_TOKEN;
    await axios.post('https://api.fonnte.com/send', {
      target: hp,
      message: `*KODE OTP OLOLU*\n\nKode Anda adalah: *${kode}*\nBerlaku selama 5 menit.`
    }, { headers: { 'Authorization': token } });
    res.json({ sukses: true, pesan: 'OTP terkirim' });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.post('/api/auth/register-pengguna', async (req, res) => {
  const { nama_lengkap, nomor_hp, kata_sandi, kode_otp } = req.body;
  const hp = nomor_hp.replace(/\D/g, '').replace(/^0/, '62');
  try {
    const otpData = await supabase('otp', 'GET', null, `?hp=eq.${hp}&kode=eq.${kode_otp}`);
    if (!otpData.length || new Date() > new Date(otpData[0].expires_at)) return res.status(400).json({ sukses: false, pesan: 'OTP tidak valid' });
    const newUser = {
      id_pengguna: 'USR' + Date.now().toString(36).toUpperCase(),
      nama_lengkap, nomor_hp: hp, kata_sandi: hashPassword(kata_sandi), status_akun: 'aktif', tanggal_daftar: new Date().toISOString()
    };
    await supabase('pengguna', 'POST', newUser);
    res.json({ sukses: true, data: { token: generateToken({ id: newUser.id_pengguna, role: 'pengguna' }), pengguna: newUser } });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.post('/api/auth/login-admin', async (req, res) => {
  const { id_pengguna, kata_sandi } = req.body;
  try {
    const data = await supabase('admins', 'GET', null, `?id_pengguna=ilike.${id_pengguna}`);
    const admin = data[0];
    if (admin && checkPassword(kata_sandi, admin.kata_sandi)) {
      res.json({ sukses: true, data: { token: generateToken({ id: admin.id_admin, role: 'admin' }), admin: { id: admin.id_admin, username: admin.id_pengguna, role: 'admin' } } });
    } else { res.status(401).json({ sukses: false, pesan: 'ID atau Password salah' }); }
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.post('/api/auth/login-pengguna', async (req, res) => {
  const { nomor_hp, kata_sandi } = req.body;
  const hp = nomor_hp.replace(/\D/g,'').replace(/^0/,'62');
  try {
    const data = await supabase('pengguna', 'GET', null, `?nomor_hp=eq.${hp}`);
    const user = data[0];
    if (user && checkPassword(kata_sandi, user.kata_sandi)) {
      res.json({ sukses: true, data: { token: generateToken({ id: user.id_pengguna, role: 'pengguna' }), pengguna: { id: user.id_pengguna, nama_lengkap: user.nama_lengkap, role: 'pengguna' } } });
    } else { res.status(401).json({ sukses: false, pesan: 'HP/Password salah' }); }
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.post('/api/auth/login-driver', async (req, res) => {
  const { nomor_hp, kode_akses } = req.body;
  const hp = nomor_hp.replace(/\D/g,'').replace(/^0/,'62');
  try {
    const data = await supabase('drivers', 'GET', null, `?nomor_hp=eq.${hp}&kode_akses=eq.${kode_akses.toUpperCase()}`);
    const d = data[0];
    if (d) {
      res.json({ sukses: true, data: { token: generateToken({ id: d.id_driver, role: 'driver' }), driver: { id: d.id_driver, nama_lengkap: d.nama_lengkap, role: 'driver' } } });
    } else { res.status(401).json({ sukses: false, pesan: 'HP/Kode salah' }); }
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 2. PESANAN ROUTES
app.post('/api/pesanan/buat', async (req, res) => {
  try {
    const id_pesanan = 'ORD-' + Date.now().toString().slice(-8).toUpperCase();
    const p = { ...req.body, id_pesanan, status_pesanan: 'mencari_driver', tanggal_waktu: new Date().toISOString() };
    await supabase('pesanan', 'POST', p);
    // Logic cari driver & notify would go here
    res.json({ sukses: true, data: p });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/pesanan/detail', async (req, res) => {
  try {
    const p = (await supabase('pesanan', 'GET', null, `?id_pesanan=eq.${req.query.id}`))[0];
    if (!p) return res.status(404).json({ sukses: false });
    const [d, u] = await Promise.all([
      p.id_driver ? supabase('drivers', 'GET', null, `?id_driver=eq.${p.id_driver}`) : Promise.resolve([]),
      p.id_pengguna ? supabase('pengguna', 'GET', null, `?id_pengguna=eq.${p.id_pengguna}`) : Promise.resolve([])
    ]);
    res.json({ sukses: true, data: { ...p, driver_info: d[0], pengguna_info: u[0] } });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 3. ADMIN ROUTES
app.get('/api/admin/dashboard', async (req, res) => {
  try {
    const [drivers, users, pesanan] = await Promise.all([supabase('drivers'), supabase('pengguna'), supabase('pesanan')]);
    res.json({ sukses: true, data: { total_driver: drivers.length, total_pengguna: users.length, pesanan_total: pesanan.length }});
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/admin/pengaturan', async (req, res) => {
  try { res.json({ sukses: true, data: (await supabase('pengaturan', 'GET', null, `?id=eq.sistem`))[0]?.data || {} }); }
  catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/admin/driver', async (req, res) => {
    try { res.json({ sukses: true, data: await supabase('drivers', 'GET', null, '?order=id_driver.asc') }); }
    catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/admin/pesanan', async (req, res) => {
    try { res.json({ sukses: true, data: await supabase('pesanan', 'GET', null, '?order=tanggal_waktu.desc') }); }
    catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/admin/pengguna', async (req, res) => {
    try { res.json({ sukses: true, data: await supabase('pengguna', 'GET', null, '?order=nama_lengkap.asc') }); }
    catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.listen(PORT, () => console.log(`Server LIVE on port ${PORT}`));
