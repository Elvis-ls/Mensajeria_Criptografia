# 🔐 SecureChat — Mensajería E2EE

Aplicación de mensajería con cifrado de extremo a extremo (E2EE) implementada como ejemplo práctico de criptografía aplicada.

---

## 🛡️ Criptografía implementada

| Técnica | Dónde se aplica | Propósito |
|---|---|---|
| **SHA-256** | Contraseñas en BD | Nunca se guarda la contraseña en texto plano |
| **SHA-256** | Tokens de sesión | El token plano solo vive en el cliente |
| **SHA-256** | Hash de mensajes | Verificar integridad al descifrar |
| **RSA-2048 (OAEP)** | Cifrar clave AES por mensaje | E2EE: solo el destinatario descifra |
| **AES-256-GCM** | Contenido del mensaje | Cifrado simétrico autenticado |

### Flujo E2EE completo

```
EMISOR (navegador)                    SERVIDOR                  RECEPTOR (navegador)
─────────────────                     ────────                  ───────────────────
1. Genera clave AES efímera
2. Cifra mensaje → AES-GCM
3. Cifra clave AES → RSA(pub_receptor)
4. Cifra clave AES → RSA(pub_emisor)
5. SHA-256(texto_plano) = hash
6. Envía todo cifrado ─────────────► Almacena cifrado
                                     (NUNCA ve texto plano)
                                              ────────────────► 7. Descifra clave AES
                                                                    → RSA(priv_receptor)
                                                               8. Descifra mensaje
                                                                    → AES-GCM
                                                               9. Verifica SHA-256
```

---

## 📁 Estructura del proyecto

```
securechat/
├── database/
│   └── schema.sql          ← Ejecutar primero
├── backend/
│   ├── server.js           ← API Node.js/Express
│   ├── package.json
│   └── .env.example        ← Copiar a .env y configurar
└── frontend/
    └── index.html          ← Abrir directamente en el navegador
```

---

## 🚀 Cómo ejecutar en local

### 1. Base de datos (MySQL)

```bash
# Opción A: línea de comandos
mysql -u root -p < database/schema.sql

# Opción B: desde MySQL Workbench
# Archivo → Abrir Script SQL → database/schema.sql → Ejecutar (⚡)

# Opción C: desde phpMyAdmin (XAMPP/WAMP)
# Importar → Seleccionar archivo → schema.sql → Continuar
```

### 2. Backend (Node.js)

**Requisitos:** Node.js 16+ y MySQL 8+

```bash
cd backend

# Copiar y configurar variables de entorno
cp .env.example .env
# Editar .env con tus credenciales de MySQL

# Instalar dependencias
npm install

# Iniciar servidor
npm start
# → API disponible en http://localhost:3001
```

### 3. Frontend

```bash
# Simplemente abre en el navegador:
# Windows:  start frontend/index.html
# macOS:    open frontend/index.html
# Linux:    xdg-open frontend/index.html

# O usa Live Server en VS Code (recomendado)
```

---

## 🔑 Notas importantes sobre las claves

- La **clave privada RSA se genera en tu navegador** al registrarte y se guarda en `sessionStorage`.
- Si cierras el navegador/pestaña, la clave privada se pierde. Para esta demo, simplemente **regístrate de nuevo**.
- En una app de producción, la clave privada se exportaría cifrada y se almacenaría de forma segura (IndexedDB cifrado con una contraseña maestra, o un HSM).

---

## 🧪 Probar la app

1. Abre la app en **dos pestañas distintas** (o dos navegadores).
2. Regístrate con un usuario diferente en cada una.
3. Desde una pestaña, inicia sesión y selecciona al otro usuario.
4. Envía un mensaje — verás el hash SHA-256 bajo cada burbuja.
5. El servidor almacena solo datos cifrados (verifica en tu BD: `SELECT * FROM messages;`).

---

## 🔧 Dependencias del backend

| Paquete | Versión | Uso |
|---|---|---|
| express | ^4.18 | Servidor HTTP |
| mysql2 | ^3.6 | Conexión MySQL |
| cors | ^2.8 | Cross-Origin |
| dotenv | ^16.3 | Variables de entorno |
| uuid | ^9.0 | Generación de tokens |
| crypto | nativo Node.js | SHA-256 |

El frontend **no tiene dependencias externas** — usa exclusivamente la Web Crypto API del navegador.
