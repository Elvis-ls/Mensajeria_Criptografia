require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3001;

// ─── Middlewares ─────────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '2mb' }));

// ─── PostgreSQL Pool ─────────────────────────────────────────────────────────
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'mensajeria_criptografia_v2',
  port: parseInt(process.env.DB_PORT || '5432'),
});

// ─── [SHA-256] Funciones criptográficas ──────────────────────────────────────

/** Genera salt aleatorio de 32 bytes */
function generateSalt() {
  return crypto.randomBytes(32).toString('hex');
}

/** Hash de contraseña: sha256(salt + password) */
function hashPassword(password, salt) {
  return crypto.createHash('sha256')
    .update(salt + password)
    .digest('hex');
}

// ═════════════════════════════════════════════════════════════════════════════
//  AUTENTICACIÓN
// ═════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/register
 * Body: { username, password, publicKey }
 */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, publicKey } = req.body;

    // Validaciones básicas
    if (!username || !password || !publicKey) {
      return res.status(400).json({ error: 'Faltan campos requeridos' });
    }

    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({ error: 'Username: 3-50 caracteres' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Contraseña mínimo 6 caracteres' });
    }

    // [SHA-256] Generar salt y hashear contraseña
    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);

    await pool.query(
      `INSERT INTO users (username, password_hash, password_salt, public_key)
       VALUES ($1, $2, $3, $4)`,
      [username.trim(), passwordHash, salt, publicKey]
    );

    res.json({ success: true, message: 'Usuario registrado' });

  } catch (err) {
    if (err.code === '23505') { // UNIQUE violation
      return res.status(409).json({ error: 'El username ya existe' });
    }
    console.error('Error en registro:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

/**
 * POST /api/login
 * Body: { username, password }
 */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Faltan credenciales' });
    }

    // Buscar usuario
    const { rows } = await pool.query(
      'SELECT id, password_hash, password_salt, public_key FROM users WHERE username = $1',
      [username]
    );

    if (!rows.length) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    const user = rows[0];

    // [SHA-256] Verificar contraseña
    const computedHash = hashPassword(password, user.password_salt);
    if (computedHash !== user.password_hash) {
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    // Marcar como online
    await pool.query('UPDATE users SET is_online = TRUE WHERE id = $1', [user.id]);

    res.json({
      success: true,
      userId: user.id,
      username: username,
      publicKey: user.public_key
    });

  } catch (err) {
    console.error('Error en login:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

/**
 * POST /api/logout
 * Body: { userId }
 */
app.post('/api/logout', async (req, res) => {
  try {
    const { userId } = req.body;
    await pool.query('UPDATE users SET is_online = FALSE WHERE id = $1', [userId]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error en logout:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
//  USUARIOS
// ═════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/users/:currentUserId
 * Obtiene lista de todos los usuarios excepto el actual
 */
app.get('/api/users/:currentUserId', async (req, res) => {
  try {
    const currentUserId = parseInt(req.params.currentUserId);

    const { rows } = await pool.query(
      `SELECT id, username, public_key, is_online 
       FROM users 
       WHERE id != $1 
       ORDER BY username`,
      [currentUserId]
    );

    res.json(rows);
  } catch (err) {
    console.error('Error obteniendo usuarios:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
//  MENSAJES (E2EE)
// ═════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/messages
 * Body: { senderId, recipientId, contentEncrypted, encryptedKey, messageHash }
 */
app.post('/api/messages', async (req, res) => {
  try {
    const { senderId, recipientId, contentEncrypted, encryptedKey, messageHash } = req.body;

    if (!senderId || !recipientId || !contentEncrypted || !encryptedKey || !messageHash) {
      return res.status(400).json({ error: 'Faltan campos del mensaje' });
    }

    const { rows } = await pool.query(
      `INSERT INTO messages 
         (sender_id, recipient_id, content_encrypted, encrypted_key, message_hash)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [senderId, recipientId, contentEncrypted, encryptedKey, messageHash]
    );

    res.json({ success: true, messageId: rows[0].id });

  } catch (err) {
    console.error('Error guardando mensaje:', err);
    res.status(500).json({ error: 'Error al guardar mensaje' });
  }
});

/**
 * GET /api/messages/:userId1/:userId2
 * Obtiene conversación entre dos usuarios
 */
app.get('/api/messages/:userId1/:userId2', async (req, res) => {
  try {
    const userId1 = parseInt(req.params.userId1);
    const userId2 = parseInt(req.params.userId2);

    const { rows } = await pool.query(
      `SELECT 
         m.id, m.sender_id, m.recipient_id,
         m.content_encrypted, m.encrypted_key, m.message_hash, m.sent_at,
         u.username AS sender_username
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       WHERE (m.sender_id = $1 AND m.recipient_id = $2)
          OR (m.sender_id = $2 AND m.recipient_id = $1)
       ORDER BY m.sent_at ASC`,
      [userId1, userId2]
    );

    res.json(rows);

  } catch (err) {
    console.error('Error obteniendo mensajes:', err);
    res.status(500).json({ error: 'Error al obtener mensajes' });
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', message: 'SecureChat Simple API funcionando' });
  } catch (err) {
    res.status(500).json({ status: 'error', message: 'BD no disponible' });
  }
});

// ─── Iniciar servidor ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════╗
  ║  SecureChat Simple - Puerto ${PORT}      ║
  ║  PostgreSQL · SHA-256 · E2EE         ║
  ╚═══════════════════════════════════════╝
  `);
});