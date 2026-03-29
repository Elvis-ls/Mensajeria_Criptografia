/**
 * SecureChat - Backend (Node.js + Express + PostgreSQL)
 * ======================================================
 * Criptografía implementada (lado servidor):
 *   [SHA-256]  → hash de contraseñas y tokens de sesión (módulo nativo 'crypto')
 *   [RSA/AES]  → solo se transportan y almacenan; el cifrado/descifrado
 *                ocurre en el CLIENTE (E2EE puro: el servidor nunca ve texto plano)
 */

require('dotenv').config();
const express        = require('express');
const cors           = require('cors');
const crypto         = require('crypto');      // módulo nativo Node.js
const { Pool }       = require('pg');          // ← PostgreSQL (antes era mysql2)
const { v4: uuidv4 } = require('uuid');

const app  = express();
const PORT = process.env.PORT || 3001;

// ─── Middlewares ─────────────────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '2mb' }));

// ─── Pool de conexiones PostgreSQL ───────────────────────────────────────────
const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  user:     process.env.DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME     || 'mensajeria_criptografia',
  port:     parseInt(process.env.DB_PORT || '5432'),
});

// ─── Utilidades criptográficas (SHA-256) ─────────────────────────────────────

/** [SHA-256] Salt aleatorio de 32 bytes */
function generateSalt() {
  return crypto.randomBytes(32).toString('hex');
}

/** [SHA-256] hash de contraseña: sha256(salt:password) */
function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(`${salt}:${password}`).digest('hex');
}

/** [SHA-256] hash del token de sesión antes de guardarlo en BD */
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// ─── Middleware de autenticación ──────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No autenticado' });

  const tokenHash = hashToken(token);
  // PostgreSQL: parámetros con $1, $2... y devuelve { rows }
  const { rows } = await pool.query(
    `SELECT s.user_id, u.username
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
    [tokenHash]
  );
  if (!rows.length) return res.status(401).json({ error: 'Sesión inválida o expirada' });

  req.userId   = rows[0].user_id;
  req.username = rows[0].username;
  next();
}

// ════════════════════════════════════════════════════════════════════════════
//  RUTAS DE AUTENTICACIÓN
// ════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/register
 * Body: { username, password, publicKey }
 */
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, publicKey } = req.body;

    if (!username || !password || !publicKey)
      return res.status(400).json({ error: 'Faltan campos requeridos' });

    if (username.length < 3 || username.length > 50)
      return res.status(400).json({ error: 'Username: 3-50 caracteres' });

    if (password.length < 6)
      return res.status(400).json({ error: 'Contraseña mínimo 6 caracteres' });

    // [SHA-256] Generar salt y hashear contraseña
    const salt         = generateSalt();
    const passwordHash = hashPassword(password, salt);

    await pool.query(
      `INSERT INTO users (username, password_hash, password_salt, public_key)
       VALUES ($1, $2, $3, $4)`,
      [username.trim(), passwordHash, salt, publicKey]
    );

    res.json({ success: true, message: 'Usuario registrado correctamente' });
  } catch (err) {
    // PostgreSQL código 23505 = violación de UNIQUE (username duplicado)
    if (err.code === '23505')
      return res.status(409).json({ error: 'El username ya existe' });
    console.error(err);
    res.status(500).json({ error: 'Error interno' });
  }
});

/**
 * POST /api/login
 * Body: { username, password }
 */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Faltan credenciales' });

    const { rows } = await pool.query(
      `SELECT id, password_hash, password_salt, public_key
         FROM users WHERE username = $1`,
      [username]
    );
    if (!rows.length)
      return res.status(401).json({ error: 'Credenciales incorrectas' });

    const user = rows[0];

    // [SHA-256] Verificar contraseña
    const computedHash = hashPassword(password, user.password_salt);
    if (computedHash !== user.password_hash)
      return res.status(401).json({ error: 'Credenciales incorrectas' });

    // Token plano (solo viaja al cliente)
    const token     = uuidv4() + '-' + uuidv4();
    const tokenHash = hashToken(token);  // [SHA-256] esto va a la BD

    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h
    await pool.query(
      `INSERT INTO sessions (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [user.id, tokenHash, expiresAt]
    );

    // Marcar online (TRUE en PostgreSQL, no 1)
    await pool.query(`UPDATE users SET is_online = TRUE WHERE id = $1`, [user.id]);

    res.json({ success: true, token, userId: user.id, username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error interno' });
  }
});

/**
 * POST /api/logout
 */
app.post('/api/logout', requireAuth, async (req, res) => {
  const token     = req.headers['authorization']?.replace('Bearer ', '');
  const tokenHash = hashToken(token);
  await pool.query(`DELETE FROM sessions WHERE token_hash = $1`, [tokenHash]);
  await pool.query(`UPDATE users SET is_online = FALSE WHERE id = $1`, [req.userId]);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════════════════════════════
//  RUTAS DE USUARIOS
// ════════════════════════════════════════════════════════════════════════════

app.get('/api/users', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, username, public_key, is_online, last_seen
       FROM users WHERE id != $1 ORDER BY username`,
    [req.userId]
  );
  res.json(rows);
});

app.get('/api/users/:id/publickey', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT public_key FROM users WHERE id = $1`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
  res.json({ publicKey: rows[0].public_key });
});

// ════════════════════════════════════════════════════════════════════════════
//  RUTAS DE MENSAJES (E2EE)
// ════════════════════════════════════════════════════════════════════════════

app.post('/api/messages', requireAuth, async (req, res) => {
  try {
    const { recipientId, contentEncrypted, iv, encryptedKeyRecipient, encryptedKeySender, messageHash } = req.body;

    if (!recipientId || !contentEncrypted || !iv || !encryptedKeyRecipient || !encryptedKeySender || !messageHash)
      return res.status(400).json({ error: 'Faltan campos del mensaje cifrado' });

    // RETURNING id → PostgreSQL para obtener el id insertado (en lugar de result.insertId de MySQL)
    const { rows } = await pool.query(
      `INSERT INTO messages
         (sender_id, recipient_id, content_encrypted, iv,
          encrypted_key_recipient, encrypted_key_sender, message_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id`,
      [req.userId, recipientId, contentEncrypted, iv, encryptedKeyRecipient, encryptedKeySender, messageHash]
    );

    res.json({ success: true, messageId: rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al guardar mensaje' });
  }
});

app.get('/api/messages/:userId', requireAuth, async (req, res) => {
  try {
    const otherId = parseInt(req.params.userId);

    // PostgreSQL: $1 y $2 se pueden reutilizar en la misma query
    const { rows } = await pool.query(
      `SELECT
         m.id, m.sender_id, m.recipient_id,
         m.content_encrypted, m.iv,
         m.encrypted_key_recipient, m.encrypted_key_sender,
         m.message_hash, m.sent_at, m.is_read,
         u.username AS sender_username
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       WHERE (m.sender_id = $1 AND m.recipient_id = $2)
          OR (m.sender_id = $2 AND m.recipient_id = $1)
       ORDER BY m.sent_at ASC`,
      [req.userId, otherId]
    );

    await pool.query(
      `UPDATE messages SET is_read = TRUE
        WHERE recipient_id = $1 AND sender_id = $2`,
      [req.userId, otherId]
    );

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al obtener mensajes' });
  }
});

app.get('/api/conversations', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT
         CASE WHEN m.sender_id = $1 THEN m.recipient_id ELSE m.sender_id END AS other_user_id,
         CASE WHEN m.sender_id = $1 THEN ur.username    ELSE us.username END AS other_username,
         MAX(m.sent_at) AS last_message_at,
         SUM(CASE WHEN m.recipient_id = $1 AND m.is_read = FALSE THEN 1 ELSE 0 END) AS unread_count
       FROM messages m
       JOIN users us ON us.id = m.sender_id
       JOIN users ur ON ur.id = m.recipient_id
       WHERE m.sender_id = $1 OR m.recipient_id = $1
       GROUP BY other_user_id, other_username
       ORDER BY last_message_at DESC`,
      [req.userId]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al obtener conversaciones' });
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', message: 'SecureChat API + PostgreSQL funcionando' });
  } catch {
    res.status(500).json({ status: 'error', message: 'BD no disponible' });
  }
});

// ─── Iniciar servidor ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════════╗
  ║   SecureChat API - Puerto ${PORT}           ║
  ║   PostgreSQL · SHA-256 · E2EE (RSA+AES) ║
  ╚══════════════════════════════════════════╝
  `);
});
