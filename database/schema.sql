-- =====================================================
-- SecureChat - Esquema de Base de Datos
-- Seguridad aplicada:
--   [1] SHA-256   → hash de contraseñas y tokens de sesión
--   [2] RSA-2048  → cifrado de claves de sesión AES (E2EE)
--   [3] AES-GCM   → cifrado del contenido de mensajes (E2EE)
-- =====================================================

CREATE DATABASE IF NOT EXISTS securechat CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE securechat;

-- =====================================================
-- TABLA: users
-- [SHA-256] password_hash: NUNCA se guarda la contraseña plana.
--           Se guarda sha256(salt + password), el salt va prefijado.
-- [RSA-E2EE] public_key: Clave pública RSA-2048 en formato SPKI/base64.
--            La clave PRIVADA jamás sale del navegador del usuario.
-- =====================================================
CREATE TABLE users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,   -- formato: sha256hex
    password_salt VARCHAR(64)  NOT NULL,   -- salt aleatorio (hex, 32 bytes)
    public_key    TEXT         NOT NULL,   -- RSA-2048 SPKI base64 (para E2EE)
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen     DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_online     TINYINT(1) DEFAULT 0
);

-- =====================================================
-- TABLA: messages
-- [AES-GCM E2EE] content_encrypted: texto cifrado con AES-256-GCM.
--                La clave AES es efímera, generada por mensaje.
-- [RSA E2EE]     encrypted_key_recipient: la clave AES cifrada con la
--                RSA pública del destinatario. Solo él puede descifrarla.
--                encrypted_key_sender: la misma clave AES cifrada con
--                la RSA pública del remitente (para que pueda releer).
-- [SHA-256]      message_hash: hash del texto plano. Permite verificar
--                integridad después de descifrar.
-- =====================================================
CREATE TABLE messages (
    id                       INT AUTO_INCREMENT PRIMARY KEY,
    sender_id                INT  NOT NULL,
    recipient_id             INT  NOT NULL,
    content_encrypted        TEXT NOT NULL,   -- AES-GCM ciphertext (base64)
    iv                       VARCHAR(32) NOT NULL,  -- nonce AES-GCM (12 bytes, base64)
    encrypted_key_recipient  TEXT NOT NULL,   -- clave AES cifrada con RSA del destinatario
    encrypted_key_sender     TEXT NOT NULL,   -- clave AES cifrada con RSA del remitente
    message_hash             VARCHAR(64) NOT NULL, -- SHA-256 del texto plano
    sent_at                  DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read                  TINYINT(1) DEFAULT 0,

    FOREIGN KEY (sender_id)    REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_conversation (sender_id, recipient_id),
    INDEX idx_recipient    (recipient_id, is_read)
);

-- =====================================================
-- TABLA: sessions
-- [SHA-256] token_hash: el token de sesión se hashea antes de guardarse.
--           El token plano solo vive en la cookie del cliente.
-- =====================================================
CREATE TABLE sessions (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT NOT NULL,
    token_hash  VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 del token de sesión
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_token (token_hash)
);

SELECT 'SecureChat DB creada exitosamente.' AS resultado;
