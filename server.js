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
    const res = await axios({
      url,
      method,
      data: body,
      headers,
      timeout: 15000
    });
    return res.data;
  } catch (e) {
    const errorMsg = e.response?.data?.message || e.message;
    console.error(`Supabase Error [${table}]:`, errorMsg);
    throw new Error(errorMsg);
  }
};

// --- ROUTES ---

app.get('/', (req, res) => res.send('OLOLU Backend is Running!'));
app.get('/api/ping', (req, res) => res.json({ sukses: true, pesan: 'Server Aktif!' }));

// 1. AUTH ROUTES
app.post('/api/auth/login-admin', async (req, res) => {
  const { id_pengguna, kata_sandi } = req.body;
  try {
    const data = await supabase('admins', 'GET', null, `?id_pengguna=ilike.${id_pengguna}`);
    const admin = data[0];
    if (admin && checkPassword(kata_sandi, admin.kata_sandi)) {
      res.json({
        sukses: true,
        data: {
          token: generateToken({ id: admin.id_admin, username: admin.id_pengguna, role: 'admin' }),
          admin: { id: admin.id_admin, username: admin.id_pengguna, role: 'admin' }
        }
      });
    } else {
      res.status(401).json({ sukses: false, pesan: 'ID atau Password Admin salah' });
    }
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

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

// 2. ADMIN DASHBOARD & STATS
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

// 3. SETTINGS
app.get('/api/admin/pengaturan', async (req, res) => {
  try {
    const data = await supabase('pengaturan', 'GET', null, `?id=eq.sistem`);
    res.json({ sukses: true, data: data[0]?.data || {} });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.put('/api/admin/pengaturan', async (req, res) => {
  try {
    await supabase('pengaturan', 'PATCH', { data: req.body }, '?id=eq.sistem');
    res.json({ sukses: true, pesan: 'Pengaturan disimpan' });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 4. DRIVER MANAGEMENT
app.get('/api/admin/driver', async (req, res) => {
    try { res.json({ sukses: true, data: await supabase('drivers', 'GET', null, '?order=id_driver.asc') }); }
    catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/admin/driver/:id', async (req, res) => {
  try {
    const data = await supabase('drivers', 'GET', null, `?id_driver=eq.${req.params.id}`);
    res.json({ sukses: true, data: data[0] });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.post('/api/admin/driver/:id/:aksi', async (req, res) => {
  const { id, aksi } = req.params;
  try {
    if (aksi === 'blokir') await supabase('drivers', 'PATCH', { status_akun: 'diblokir' }, `?id_driver=eq.${id}`);
    if (aksi === 'aktifkan') await supabase('drivers', 'PATCH', { status_akun: 'aktif' }, `?id_driver=eq.${id}`);
    if (aksi === 'reset-kode') {
      const newKode = Math.floor(100000 + Math.random() * 900000).toString();
      await supabase('drivers', 'PATCH', { kode_akses: newKode }, `?id_driver=eq.${id}`);
      return res.json({ sukses: true, data: { kode_akses: newKode } });
    }
    if (aksi === 'topup') {
      const driver = (await supabase('drivers', 'GET', null, `?id_driver=eq.${id}`))[0];
      const newSaldo = (driver.saldo_kredit || 0) + parseInt(req.body.nominal);
      await supabase('drivers', 'PATCH', { saldo_kredit: newSaldo }, `?id_driver=eq.${id}`);
      return res.json({ sukses: true, pesan: 'Saldo diperbarui', data: { saldo_kredit: newSaldo } });
    }
    res.json({ sukses: true });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 5. USER MANAGEMENT
app.get('/api/admin/pengguna', async (req, res) => {
    try { res.json({ sukses: true, data: await supabase('pengguna', 'GET', null, '?order=nama_lengkap.asc') }); }
    catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.post('/api/admin/pengguna/:id/:aksi', async (req, res) => {
  const { id, aksi } = req.params;
  try {
    if (aksi === 'blokir') await supabase('pengguna', 'PATCH', { status_akun: 'diblokir' }, `?id_pengguna=eq.${id}`);
    if (aksi === 'aktifkan') await supabase('pengguna', 'PATCH', { status_akun: 'aktif' }, `?id_pengguna=eq.${id}`);
    res.json({ sukses: true });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 6. ORDER MANAGEMENT & MAP
app.get('/api/admin/pesanan', async (req, res) => {
    try { res.json({ sukses: true, data: await supabase('pesanan', 'GET', null, '?order=tanggal_waktu.desc&limit=100') }); }
    catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/pesanan/peta', async (req, res) => {
  try {
    const drivers = await supabase('drivers', 'GET', null, "?status_operasi=neq.offline");
    const mapData = drivers.map(d => ({
      id_driver: d.id_driver,
      nama: d.nama_lengkap,
      lat: d.lokasi_lat,
      lng: d.lokasi_lng,
      status_operasi: d.status_operasi,
      jenis_motor: d.jenis_motor,
      rating: d.rating_rata
    })).filter(d => d.lat && d.lng);
    res.json({ sukses: true, data: mapData });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.get('/api/pesanan/detail', async (req, res) => {
  try {
    const id = req.query.id;
    const data = await supabase('pesanan', 'GET', null, `?id_pesanan=eq.${id}`);
    const p = data[0];
    if (!p) return res.status(404).json({ sukses: false, pesan: 'Tidak ditemukan' });

    // Join manually for info
    const [d, u] = await Promise.all([
      p.id_driver ? supabase('drivers', 'GET', null, `?id_driver=eq.${p.id_driver}`) : Promise.resolve([]),
      p.id_pengguna ? supabase('pengguna', 'GET', null, `?id_pengguna=eq.${p.id_pengguna}`) : Promise.resolve([])
    ]);

    res.json({
      sukses: true,
      data: {
        ...p,
        driver_info: d[0] ? { nama: d[0].nama_lengkap, nomor_plat: d[0].nomor_plat } : null,
        pengguna_info: u[0] ? { nama: u[0].nama_lengkap, nomor_hp: u[0].nomor_hp } : null
      }
    });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

// 7. DEPOSITS
app.get('/api/admin/setoran', async (req, res) => {
  try {
    const data = await supabase('setoran', 'GET', null, '?order=tanggal_setor.desc&limit=50');
    // Join with driver names
    const drivers = await supabase('drivers', 'GET', null, '?select=id_driver,nama_lengkap');
    const result = data.map(s => {
      const d = drivers.find(dr => dr.id_driver === s.id_driver);
      return { ...s, driver_nama: d ? d.nama_lengkap : s.id_driver };
    });
    res.json({ sukses: true, data: result });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.post('/api/admin/setoran/:id/:aksi', async (req, res) => {
  const { id, aksi } = req.params;
  try {
    if (aksi === 'verifikasi') {
      const setoran = (await supabase('setoran', 'GET', null, `?id_setoran=eq.${id}`))[0];
      if (setoran && setoran.status === 'belum_diverifikasi') {
        const driver = (await supabase('drivers', 'GET', null, `?id_driver=eq.${setoran.id_driver}`))[0];
        await Promise.all([
          supabase('setoran', 'PATCH', { status: 'lunas' }, `?id_setoran=eq.${id}`),
          supabase('drivers', 'PATCH', { saldo_kredit: (driver.saldo_kredit || 0) + setoran.nominal }, `?id_driver=eq.${setoran.id_driver}`)
        ]);
      }
    } else if (aksi === 'tolak') {
      await supabase('setoran', 'PATCH', { status: 'ditolak' }, `?id_setoran=eq.${id}`);
    }
    res.json({ sukses: true });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.listen(PORT, () => console.log(`Server OLOLU UNLIMITED LIVE on port ${PORT}`));
