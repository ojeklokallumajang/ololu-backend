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

// 1. KIRIM OTP (VIA FONNTE)
app.post('/api/auth/kirim-otp', async (req, res) => {
  const { nomor_hp } = req.body;
  if (!nomor_hp) return res.status(400).json({ sukses: false, pesan: 'Nomor HP wajib diisi' });

  const hp = nomor_hp.replace(/\D/g, '').replace(/^0/, '62');
  const kode = Math.floor(100000 + Math.random() * 900000).toString();
  const expires_at = new Date(Date.now() + 5 * 60000).toISOString(); // 5 menit

  try {
    // Simpan ke tabel OTP Supabase
    await supabase('otp', 'POST', { hp, kode, expires_at });

    // Kirim via Fonnte
    const token = process.env.FONNTE_TOKEN;
    if (!token) throw new Error('FONNTE_TOKEN belum diset di server!');

    await axios.post('https://api.fonnte.com/send', {
      target: hp,
      message: `*KODE OTP OLOLU*\n\nKode Anda adalah: *${kode}*\nJangan berikan kode ini kepada siapapun.\n\nBerlaku selama 5 menit.`
    }, { headers: { 'Authorization': token } });

    res.json({ sukses: true, pesan: 'OTP berhasil dikirim ke WhatsApp Anda' });
  } catch (e) {
    console.error('Gagal Kirim OTP:', e.message);
    res.status(500).json({ sukses: false, pesan: 'Gagal kirim OTP: ' + e.message });
  }
});

// 2. REGISTER PENGGUNA
app.post('/api/auth/register-pengguna', async (req, res) => {
  const { nama_lengkap, nomor_hp, kata_sandi, kode_otp } = req.body;
  const hp = nomor_hp.replace(/\D/g, '').replace(/^0/, '62');

  try {
    // Verifikasi OTP
    const otpData = await supabase('otp', 'GET', null, `?hp=eq.${hp}&kode=eq.${kode_otp}`);
    if (!otpData.length) return res.status(400).json({ sukses: false, pesan: 'Kode OTP salah' });

    if (new Date() > new Date(otpData[0].expires_at)) return res.status(400).json({ sukses: false, pesan: 'OTP kedaluwarsa' });

    // Cek duplikasi
    const existing = await supabase('pengguna', 'GET', null, `?nomor_hp=eq.${hp}`);
    if (existing.length) return res.status(400).json({ sukses: false, pesan: 'Nomor HP sudah terdaftar' });

    // Simpan User Baru
    const newUser = {
      id_pengguna: 'USR' + Date.now().toString(36).toUpperCase(),
      nama_lengkap,
      nomor_hp: hp,
      kata_sandi: hashPassword(kata_sandi),
      status_akun: 'aktif',
      tanggal_daftar: new Date().toISOString()
    };
    await supabase('pengguna', 'POST', newUser);

    // Hapus OTP setelah sukses
    await supabase('otp', 'DELETE', null, `?hp=eq.${hp}`);

    res.json({ sukses: true, data: { token: generateToken({ id: newUser.id_pengguna, role: 'pengguna' }), pengguna: newUser } });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 3. LOGIN ADMIN
app.post('/api/auth/login-admin', async (req, res) => {
  const { id_pengguna, kata_sandi } = req.body;
  try {
    const data = await supabase('admins', 'GET', null, `?id_pengguna=ilike.${id_pengguna}`);
    const admin = data[0];
    if (admin && checkPassword(kata_sandi, admin.kata_sandi)) {
      res.json({ sukses: true, data: { token: generateToken({ id: admin.id_admin, role: 'admin' }), admin: { id: admin.id_admin, username: admin.id_pengguna, role: 'admin' } } });
    } else {
      res.status(401).json({ sukses: false, pesan: 'ID atau Password Admin salah' });
    }
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 4. LOGIN PENGGUNA
app.post('/api/auth/login-pengguna', async (req, res) => {
  const { nomor_hp, kata_sandi } = req.body;
  try {
    const hp = nomor_hp.replace(/\D/g,'').replace(/^0/,'62');
    const data = await supabase('pengguna', 'GET', null, `?nomor_hp=eq.${hp}`);
    const user = data[0];
    if (user && checkPassword(kata_sandi, user.kata_sandi)) {
      res.json({ sukses: true, data: { token: generateToken({ id: user.id_pengguna, role: 'pengguna' }), pengguna: { id: user.id_pengguna, nama_lengkap: user.nama_lengkap, role: 'pengguna' } } });
    } else {
      res.status(401).json({ sukses: false, pesan: 'Nomor HP atau Password salah' });
    }
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 5. LOGIN DRIVER
app.post('/api/auth/login-driver', async (req, res) => {
  const { nomor_hp, kode_akses } = req.body;
  try {
    const hp = nomor_hp.replace(/\D/g,'').replace(/^0/,'62');
    const data = await supabase('drivers', 'GET', null, `?nomor_hp=eq.${hp}&kode_akses=eq.${kode_akses.toUpperCase()}`);
    const d = data[0];
    if (d) {
      res.json({ sukses: true, data: { token: generateToken({ id: d.id_driver, role: 'driver' }), driver: { id: d.id_driver, nama_lengkap: d.nama_lengkap, role: 'driver' } } });
    } else {
      res.status(401).json({ sukses: false, pesan: 'Nomor HP atau Kode Akses salah' });
    }
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 6. DASHBOARD ADMIN
app.get('/api/admin/dashboard', async (req, res) => {
  try {
    const [drivers, users, pesanan, setoran] = await Promise.all([
      supabase('drivers'),
      supabase('pengguna'),
      supabase('pesanan', 'GET', null, '?order=tanggal_waktu.desc'),
      supabase('setoran', 'GET', null, '?status=eq.belum_diverifikasi')
    ]);
    res.json({
      sukses: true,
      data: {
        total_driver: drivers.length,
        driver_aktif: drivers.filter(d => d.status_operasi === 'siap').length,
        total_pengguna: users.length,
        pesanan_total: pesanan.length,
        pesanan_hari_ini: pesanan.filter(p => new Date(p.tanggal_waktu).toDateString() === new Date().toDateString()).length,
        setoran_pending: setoran.length
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
