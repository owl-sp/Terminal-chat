/**
 * client.js
 * ---------
 * Chat client that connects to the TLS server.
 * Launched by terminal-chat.js (bin) with connection details supplied via
 * environment variables so they never appear in `ps` output.
 *
 * Features:
 *  - TLS transport (self-signed cert accepted; traffic is still encrypted)
 *  - Public messages: plain text broadcast to every connected user
 *  - Private messages (/pm <ID> <text>): end-to-end encrypted with AES-256-GCM
 *    using the sender's random 32-byte session key
 *  - Keep-alive: responds to __PING__ frames sent by the server every 30 s
 *  - DoS protection: disconnects if the TCP receive buffer exceeds 1 MB
 */

const tls      = require('tls');
const readline = require('readline');
const crypto   = require('crypto');

// ── Connection parameters (set by terminal-chat.js via env) ─────────────────
const host   = process.env.CHAT_HOST;   // server IP or hostname
const port   = process.env.CHAT_PORT;   // server port number (string)
const name   = process.env.CHAT_NAME;   // display name chosen by the user
const userId = process.env.CHAT_ID;     // 4-char random ID, e.g. "AB47"

// Abort immediately if any required env variable is missing
if (!host || !port || !name || !userId) {
  console.error('Error: Missing connection info. Please run via terminal-chat.');
  process.exit(1);
}

// ── Readline interface (terminal I/O) ────────────────────────────────────────
const rl = readline.createInterface({
  input:  process.stdin,
  output: process.stdout,
  prompt: '> '
});

// ── End-to-End Encryption setup ──────────────────────────────────────────────

// Each session gets a fresh random 256-bit symmetric key.
// This key is shared with other clients so they can decrypt our private messages.
const secretKey = crypto.randomBytes(32);

// Cache of other users' public (session) keys, keyed by their user ID.
// Populated from `key_announce` messages sent by the server whenever a user joins.
const userKeys = {};

// ── Utility: clear the current terminal input line ───────────────────────────
// Prevents incoming messages from mixing visually with the user's typed text.
// Guarded by isTTY because clearLine/cursorTo crash in non-TTY environments
// (e.g., piped stdin during testing).
function clearLine() {
  if (process.stdout.isTTY) {
    process.stdout.clearLine(0);
    process.stdout.cursorTo(0);
  }
}

// ── AES-256-GCM helpers ──────────────────────────────────────────────────────

/**
 * Encrypts a UTF-8 string with AES-256-GCM.
 * Returns a JSON string containing the random IV, authentication tag, and
 * ciphertext — all hex-encoded — so it can be safely embedded in JSON payloads.
 *
 * @param {string} msg  - Plaintext to encrypt
 * @param {Buffer} key  - 32-byte symmetric key
 * @returns {string}    - Serialised JSON envelope
 */
function encrypt(msg, key) {
  const iv      = crypto.randomBytes(12);                               // 96-bit IV for GCM
  const cipher  = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(msg, 'utf8'), cipher.final()]);
  const tag     = cipher.getAuthTag();                                  // 128-bit AEAD tag

  return JSON.stringify({
    iv:   iv.toString('hex'),
    tag:  tag.toString('hex'),
    data: encrypted.toString('hex')
  });
}

/**
 * Decrypts a JSON envelope produced by `encrypt()`.
 * Returns '[Could not decrypt]' on any error (wrong key, corrupted data, etc.)
 * so the chat UI never crashes on a bad message.
 *
 * @param {string} encryptedStr - JSON envelope from `encrypt()`
 * @param {Buffer} key          - 32-byte symmetric key
 * @returns {string}            - Decrypted plaintext or error string
 */
function decrypt(encryptedStr, key) {
  try {
    const obj      = JSON.parse(encryptedStr);
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(obj.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(obj.tag, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(obj.data, 'hex')),
      decipher.final()
    ]);
    return decrypted.toString('utf8');
  } catch {
    return '[Could not decrypt]';
  }
}

// ── TLS connection ───────────────────────────────────────────────────────────

// `rejectUnauthorized: false` accepts the server's self-signed certificate.
// The connection is still TLS-encrypted; we just skip CA chain validation.
const socket = tls.connect({ host, port: Number(port), rejectUnauthorized: false }, () => {
  console.log('Connected to server');

  // Send the initial handshake frame so the server can register this client.
  // We include our session key so other users can send us private messages.
  const initObj = { name, id: userId, key: secretKey.toString('hex') };
  socket.write(JSON.stringify(initObj) + '\n');

  rl.prompt(); // show the input prompt after connecting
});

// ── Incoming message handling ────────────────────────────────────────────────

const MAX_BUFFER = 1024 * 1024; // 1 MB hard limit — drop connection if exceeded
let buffer = '';                 // accumulates partial TCP frames between 'data' events

socket.on('data', data => {
  buffer += data.toString();

  // Guard against malicious or buggy senders flooding the buffer with no newlines
  if (buffer.length > MAX_BUFFER) {
    console.error('Buffer overflow: too much data without newline. Disconnecting.');
    socket.destroy();
    return;
  }

  // Messages are newline-delimited; split and keep the trailing incomplete chunk
  const lines = buffer.split('\n');
  buffer = lines.pop(); // last element is the incomplete (or empty) tail

  for (const raw of lines) {
    const message = raw.trim();
    if (!message) continue;

    // ── Keep-alive: server sends __PING__ every 30 s; reply with __PONG__ ──
    if (message === '__PING__') {
      socket.write('__PONG__\n');
      continue;
    }

    // ── Try to parse as a structured JSON message ──────────────────────────
    try {
      const obj = JSON.parse(message);

      // Server is broadcasting a newly connected user's session key.
      // Store it so we can send them encrypted private messages.
      if (obj.type === 'key_announce') {
        userKeys[obj.id] = Buffer.from(obj.key, 'hex');
        continue;
      }

      // Incoming private message encrypted with the sender's session key
      if (obj.type === 'pm') {
        // Opportunistically update the sender's key if it was bundled in the payload
        if (obj.senderKey) userKeys[obj.from] = Buffer.from(obj.senderKey, 'hex');

        const senderKey = userKeys[obj.from];

        // Can't decrypt if we never received the sender's key
        if (!senderKey) {
          clearLine();
          console.log(`[PRIVATE] From ${obj.name}: [Could not decrypt - no key]`);
          rl.prompt(true);
          continue;
        }

        const decrypted = decrypt(obj.msg, senderKey);
        clearLine();
        console.log(`[PRIVATE] From ${obj.name}: ${decrypted}`);
        rl.prompt(true);
        continue;
      }
    } catch {
      // Not valid JSON — fall through to plain-text handling below
    }

    // ── Plain-text public message ──────────────────────────────────────────
    clearLine();
    console.log(message);
    rl.prompt(true);
  }
});

// ── Outgoing message handling ────────────────────────────────────────────────

rl.on('line', line => {
  line = line.trim();
  if (!line) return rl.prompt(); // ignore empty input

  // ── Private message command: /pm <targetId> <message text> ────────────────
  if (line.startsWith('/pm')) {
    const parts = line.split(' ');

    if (parts.length < 3) {
      console.log('Usage: /pm <ID> <message>');
      return rl.prompt();
    }

    const targetId = parts[1];
    const msg      = parts.slice(2).join(' ');

    // Build a structured JSON private-message payload.
    // The message body is encrypted with *our* session key so only the
    // recipient (who received our key via key_announce) can read it.
    const payload = JSON.stringify({
      type:      'pm',
      from:      userId,
      name,
      to:        targetId,
      senderKey: secretKey.toString('hex'), // include key for late-joining recipients
      msg:       encrypt(msg, secretKey)
    });

    socket.write(payload + '\n');
    console.log(`[PRIVATE] To ${targetId}: ${msg}`); // echo locally
    rl.prompt();
    return;
  }

  // ── Public message: sent as plain text; server broadcasts it to all ────────
  socket.write(line + '\n');
  rl.prompt();
});

// ── Note on keep-alive design ────────────────────────────────────────────────
// Keep-alive is entirely server-driven:
//   server  ──__PING__──▶  client
//   server  ◀─__PONG__──   client
// The client never initiates __PONG__ on its own.

// ── Connection lifecycle ─────────────────────────────────────────────────────
socket.on('end',   ()    => { console.log('Disconnected from server'); process.exit(0); });
socket.on('error', err   => { console.error('Connection error:', err.message);          process.exit(1); });