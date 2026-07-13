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

// --- UTILS (DISTANCE & PRICING) ---
function hitungJarak(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
            Math.sin(dLng / 2) * Math.sin(dLng / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function isJamOperasional(buka, tutup) {
  const now = new Date().toLocaleTimeString('id-ID', { hour12: false, hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Jakarta' });
  if (tutup < buka) return now >= buka || now <= tutup;
  return now >= buka && now <= tutup;
}

function hitungRincianTarif(jarak_km, jenis_pesanan, cfg, opsi = {}) {
  const d = {
    tarif_ojek: 7000, tarif_makanan: 7000, tarif_pasar: 8000,
    tarif_toko: 8000, tarif_barang: 8000, tarif_per_km_tambahan: 2000,
    batas_km_dasar: 4, biaya_per_stop: 3000, biaya_parkir: 2000,
    biaya_parkir_pasar: 3000, pengali_prioritas: 2,
    jam_panas_mulai: '16:00', jam_panas_selesai: '19:00', pengali_jam_panas: 1.5,
    biaya_non_tunai: 2000, biaya_menu_varian: 1000,
  };
  const c = { ...d, ...cfg };
  const j = Math.ceil(jarak_km);
  const jenis = opsi.jenis_layanan || 'ojek_penumpang';

  let tarif_dasar = 0;
  if (jenis === 'ojek_penumpang' || jenis === 'ambil_makanan') tarif_dasar = Number(c.tarif_ojek);
  else if (jenis === 'antar_makanan') tarif_dasar = Number(c.tarif_makanan);
  else if (jenis === 'belanja_pasar') tarif_dasar = Number(c.tarif_pasar);
  else if (jenis === 'belanja_toko') tarif_dasar = Number(c.tarif_toko);
  else tarif_dasar = Number(c.tarif_barang);

  let km_tambahan = j > Number(c.batas_km_dasar) ? j - Number(c.batas_km_dasar) : 0;
  let biaya_km_tambahan = km_tambahan * Number(c.tarif_per_km_tambahan);

  let biaya_varian = 0;
  const perRestoItems = opsi.per_resto_items || [];
  if (perRestoItems.length > 0) {
    perRestoItems.forEach(items => {
      if (items.length > 1) biaya_varian += (items.length - 1) * Number(c.biaya_menu_varian);
    });
  }

  let subtotal = tarif_dasar + biaya_km_tambahan + biaya_varian;
  let biaya_prioritas = (jenis_pesanan === 'prioritas') ? subtotal * (Number(c.pengali_prioritas) - 1) : 0;

  let biaya_jam_panas = 0;
  if (isJamOperasional(c.jam_panas_mulai, c.jam_panas_selesai)) {
    biaya_jam_panas = (subtotal + biaya_prioritas) * (Number(c.pengali_jam_panas || 1) - 1);
  }

  const biaya_stop = (Number(opsi.jumlah_stop) || 0) * Number(c.biaya_per_stop);
  const biaya_non_tunai = (opsi.metode_pembayaran && opsi.metode_pembayaran !== 'tunai') ? Number(c.biaya_non_tunai) : 0;

  return {
    tarif_dasar, km_tambahan, biaya_km_tambahan, biaya_varian,
    biaya_prioritas, biaya_jam_panas, biaya_stop, biaya_non_tunai,
    total: Math.ceil((subtotal + biaya_prioritas + biaya_jam_panas + biaya_stop + biaya_non_tunai) / 100) * 100
  };
}

// --- HELPER SUPABASE ---
const supabase = async (table, method = 'GET', body = null, query = '') => {
  const baseUrl = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const url = `${baseUrl}/rest/v1/${table}${query}`;
  const apiKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

  if (!baseUrl || !apiKey) throw new Error('Missing Config!');

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

// 1. AUTH
app.post('/api/auth/kirim-otp', async (req, res) => {
  const { nomor_hp } = req.body;
  const hp = nomor_hp.replace(/\D/g, '').replace(/^0/, '62');
  const kode = Math.floor(100000 + Math.random() * 900000).toString();
  const expires_at = new Date(Date.now() + 5 * 60000).toISOString();
  try {
    // FIX: Cek dulu apakah sudah ada OTP untuk nomor ini
    const existing = await supabase('otp', 'GET', null, `?hp=eq.${hp}`);
    if (existing.length) {
        await supabase('otp', 'PATCH', { kode, expires_at }, `?hp=eq.${hp}`);
    } else {
        await supabase('otp', 'POST', { hp, kode, expires_at });
    }

    await axios.post('https://api.fonnte.com/send', {
      target: hp,
      message: `*KODE OTP OLOLU*\n\nKode Anda adalah: *${kode}*\nBerlaku selama 5 menit.`
    }, { headers: { 'Authorization': process.env.FONNTE_TOKEN } });
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
    // Hapus OTP setelah berhasil
    await supabase('otp', 'DELETE', null, `?hp=eq.${hp}`);
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

// 2. PESANAN
app.post('/api/pesanan/cek-harga', async (req, res) => {
  const { titik_jemput_lat, titik_jemput_lng, titik_tujuan_lat, titik_tujuan_lng, titik_stop = [], jenis_layanan, jenis_pesanan, metode_pembayaran, per_resto_items } = req.body;
  try {
    const cfg = (await supabase('pengaturan', 'GET', null, `?id=eq.sistem`))[0]?.data || {};
    const semua_titik = [{ lat: titik_jemput_lat, lng: titik_jemput_lng }, ...titik_stop, { lat: titik_tujuan_lat, lng: titik_tujuan_lng }];
    let jarak_km = 0;
    for (let i = 0; i < semua_titik.length - 1; i++) {
        jarak_km += hitungJarak(semua_titik[i].lat, semua_titik[i].lng, semua_titik[i+1].lat, semua_titik[i+1].lng);
    }
    const rincian_biasa = hitungRincianTarif(jarak_km, 'biasa', cfg, { jenis_layanan, metode_pembayaran, jumlah_stop: titik_stop.length, per_resto_items });
    const rincian_prioritas = hitungRincianTarif(jarak_km, 'prioritas', cfg, { jenis_layanan, metode_pembayaran, jumlah_stop: titik_stop.length, per_resto_items });
    res.json({ sukses: true, data: { jarak_km: Math.round(jarak_km * 10) / 10, rincian_biasa, rincian_prioritas } });
  } catch (e) { res.status(500).json({ sukses: false, pesan: e.message }); }
});

app.post('/api/pesanan/buat', async (req, res) => {
  const { jenis_layanan, jenis_pesanan, metode_pembayaran, catatan, titik_jemput_lat, titik_jemput_lng, titik_jemput_alamat, titik_tujuan_lat, titik_tujuan_lng, titik_tujuan_alamat, titik_stop, titik_jemput_items } = req.body;
  try {
    const authHeader = req.headers.get?.('Authorization') || req.headers.authorization;
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);

    const cfg = (await supabase('pengaturan', 'GET', null, `?id=eq.sistem`))[0]?.data || {};
    const semua_titik = [{ lat: titik_jemput_lat, lng: titik_jemput_lng }, ...titik_stop, { lat: titik_tujuan_lat, lng: titik_tujuan_lng }];
    let jarak_km = 0;
    for (let i = 0; i < semua_titik.length - 1; i++) {
        jarak_km += hitungJarak(semua_titik[i].lat, semua_titik[i].lng, semua_titik[i+1].lat, semua_titik[i+1].lng);
    }

    const rincian = hitungRincianTarif(jarak_km, jenis_pesanan, cfg, { jenis_layanan, metode_pembayaran, jumlah_stop: titik_stop.length });
    const id_pesanan = 'ORD-' + Date.now().toString(36).toUpperCase();

    const p = {
      id_pesanan, id_pengguna: decoded.id, id_driver: null,
      jenis_layanan, jenis_pesanan, metode_pembayaran, catatan,
      titik_jemput: { lat: titik_jemput_lat, lng: titik_jemput_lng, alamat: titik_jemput_alamat, items: titik_jemput_items },
      titik_tujuan: { lat: titik_tujuan_lat, lng: titik_tujuan_lng, alamat: titik_tujuan_alamat },
      titik_stop, jarak_tempuh: jarak_km, tarif_total: rincian.total, tarif_layanan: rincian.total,
      status_pesanan: 'mencari_driver', tanggal_waktu: new Date().toISOString()
    };

    await supabase('pesanan', 'POST', p);
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

// 3. ADMIN
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
