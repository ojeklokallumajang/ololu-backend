const express = require('express');
const cors = require('cors');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ololu-secret-key-lumajang-2024-xK9mP';

app.use(cors());
app.use(express.json());

// Log untuk Debugging di Render
app.use((req, res, next) => {
  console.log(`>>> ${req.method} ${req.url}`);
  if (req.method === 'POST') console.log('Body:', JSON.stringify(req.body));
  next();
});

// --- FUNGSI KEAMANAN ---
function checkPassword(password, stored) {
  if (!stored || !password) return false;
  if (stored.startsWith('plain:')) {
    return password === stored.slice(6);
  }
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const derived = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha256').toString('hex');
  return derived === hash;
}

const generateToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

// --- HELPER SUPABASE ---
const supabase = async (table, method = 'GET', body = null, query = '') => {
  // Bersihkan URL dari trailing slash agar tidak terjadi double slash //rest/v1
  const baseUrl = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const url = `${baseUrl}/rest/v1/${table}${query}`;
  const apiKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

  if (!baseUrl || !apiKey) {
    throw new Error('CRITICAL: SUPABASE_URL or KEY is not set in Render Environment Variables!');
  }

  const headers = {
    'apikey': apiKey,
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
  };

  try {
    console.log(`[Supabase] Requesting: ${method} ${url}`);
    const res = await axios({
      url,
      method,
      data: body,
      headers,
      timeout: 10000 // Batalkan jika lebih dari 10 detik
    });
    console.log(`[Supabase] Success: ${table}`);
    return res.data;
  } catch (e) {
    const errorMsg = e.response?.data?.message || e.message;
    console.error(`[Supabase Error] ${table}:`, errorMsg);
    throw new Error(errorMsg);
  }
};

// --- ROUTES ---

app.get('/', (req, res) => res.send('OLOLU Backend is Running!'));
app.get('/api/ping', (req, res) => res.json({ sukses: true, pesan: 'Server Aktif!' }));

// 1. LOGIN ADMIN
app.post('/api/auth/login-admin', async (req, res) => {
  const { id_pengguna, kata_sandi } = req.body;
  try {
    const data = await supabase('admins', 'GET', null, `?id_pengguna=ilike.${id_pengguna}`);
    const admin = data[0];

    if (admin && checkPassword(kata_sandi, admin.kata_sandi)) {
      console.log('Login Admin Berhasil:', id_pengguna);
      res.json({
        sukses: true,
        data: {
          token: generateToken({ id: admin.id_admin, username: admin.id_pengguna, role: 'admin' }),
          admin: { id: admin.id_admin, username: admin.id_pengguna, role: 'admin' }
        }
      });
    } else {
      console.log('Login Admin Gagal: ID/Pass salah');
      res.status(401).json({ sukses: false, pesan: 'ID atau Password Admin salah' });
    }
  } catch (e) {
    res.status(500).json({ sukses: false, pesan: 'Database Error: ' + e.message });
  }
});

// 2. LOGIN PENGGUNA
app.post('/api/auth/login-pengguna', async (req, res) => {
  const { nomor_hp, kata_sandi } = req.body;
  try {
    const hp = nomor_hp.replace(/\D/g,'').replace(/^0/,'62');
    const data = await supabase('pengguna', 'GET', null, `?nomor_hp=eq.${hp}`);
    const user = data[0];
    if (user && checkPassword(kata_sandi, user.kata_sandi)) {
      res.json({
        sukses: true,
        data: {
          token: generateToken({ id: user.id_pengguna, role: 'pengguna' }),
          pengguna: { id: user.id_pengguna, nama_lengkap: user.nama_lengkap, role: 'pengguna' }
        }
      });
    } else {
      res.status(401).json({ sukses: false, pesan: 'Nomor HP atau Password salah' });
    }
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 3. LOGIN DRIVER
app.post('/api/auth/login-driver', async (req, res) => {
  const { nomor_hp, kode_akses } = req.body;
  try {
    const hp = nomor_hp.replace(/\D/g,'').replace(/^0/,'62');
    const data = await supabase('drivers', 'GET', null, `?nomor_hp=eq.${hp}&kode_akses=eq.${kode_akses.toUpperCase()}`);
    const d = data[0];
    if (d) {
      res.json({
        sukses: true,
        data: {
          token: generateToken({ id: d.id_driver, role: 'driver' }),
          driver: { id: d.id_driver, nama_lengkap: d.nama_lengkap, role: 'driver' }
        }
      });
    } else {
      res.status(401).json({ sukses: false, pesan: 'Nomor HP atau Kode Akses salah' });
    }
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 4. ADMIN DASHBOARD & MANAGEMENT
app.get('/api/admin/dashboard', async (req, res) => {
  try {
    const [drivers, users, pesanan] = await Promise.all([
      supabase('drivers'),
      supabase('pengguna'),
      supabase('pesanan')
    ]);
    res.json({
      sukses: true,
      data: {
        total_driver: drivers.length,
        driver_aktif: drivers.filter(d => d.status_akun === 'aktif').length,
        total_pengguna: users.length,
        pesanan_total: pesanan.length,
        setoran_pending: 0
      }
    });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/admin/pengaturan', async (req, res) => {
  try {
    const data = await supabase('pengaturan', 'GET', null, `?id=eq.sistem`);
    res.json({ sukses: true, data: data[0]?.data || {} });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/admin/driver', async (req, res) => {
    try { res.json({ sukses: true, data: await supabase('drivers', 'GET', null, '?order=id_driver.asc') }); }
    catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/admin/pesanan', async (req, res) => {
    try { res.json({ sukses: true, data: await supabase('pesanan', 'GET', null, '?order=tanggal_waktu.desc&limit=100') }); }
    catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/admin/pengguna', async (req, res) => {
    try { res.json({ sukses: true, data: await supabase('pengguna', 'GET', null, '?order=nama_lengkap.asc') }); }
    catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.listen(PORT, () => console.log(`Server OLOLU UNLIMITED LIVE on port ${PORT}`));
