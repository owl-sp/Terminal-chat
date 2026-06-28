# 🔐 Terminal Chat

A secure, end-to-end encrypted terminal chat application built with Node.js.  
No dependencies. No cloud. No registration. Just open a terminal and talk.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Starting a Server](#1-starting-a-server)
  - [Connecting as a Client](#2-connecting-as-a-client)
  - [Stopping a Server](#3-stopping-a-server)
- [In-Chat Commands](#in-chat-commands)
- [Private Messaging](#private-messaging)
- [Admin Controls](#admin-controls)
- [Project Structure](#project-structure)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Overview

Terminal Chat is a self-hosted, LAN/internet chat application that runs entirely in your terminal. It uses **TLS** to encrypt the transport layer and **AES-256-GCM** for end-to-end encrypted private messages — the server never sees private message content.

All you need is Node.js and `openssl` on your PATH.

---

## Features

| Feature | Details |
|---|---|
| 🔐 TLS Transport | All traffic is encrypted in transit using a self-signed TLS certificate |
| 🔒 E2E Private Messages | Private messages are encrypted client-side with AES-256-GCM; the server only routes the ciphertext |
| 👥 Public Chat | Broadcast messages visible to all connected users |
| 🧑‍💼 Admin Role | Password-protected admin elevation with `/admin` command |
| 🚫 Ban System | Admins can ban users by ID; bans persist for the lifetime of the server process |
| ❤️ Keep-Alive | Server sends `__PING__` every 30 seconds; client replies `__PONG__` to detect dead connections |
| 🛡️ DoS Protection | Per-client 1 MB receive buffer limit — oversized payloads drop the connection immediately |
| 📦 Zero Dependencies | Uses only Node.js built-in modules (`tls`, `crypto`, `readline`, `fs`, `child_process`) |
| 🖥️ Background Server | Server runs as a detached background process tracked by a PID file |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        terminal-chat (CLI)                       │
│  bin/terminal-chat.js                                            │
│  ┌─────────────┐  ┌──────────────────────┐  ┌────────────────┐  │
│  │  [1] Start  │  │   [2] Connect        │  │  [3] Stop      │  │
│  │   Server    │  │   Client             │  │  Server        │  │
│  └──────┬──────┘  └──────────┬───────────┘  └───────┬────────┘  │
│         │                    │                       │           │
│    spawn (detached)     spawn (inherit)         kill (PID file)  │
│         │                    │                                   │
└─────────┼────────────────────┼───────────────────────────────────┘
          │                    │
          ▼                    ▼
   lib/server.js         lib/client.js
   (TLS server)          (TLS client)
          │                    │
          └────────TLS─────────┘
              (encrypted tunnel)
```

**Message flow:**

```
Public message:
  client A  ──plain text──▶  server  ──broadcast──▶  all other clients

Private message (/pm):
  client A  ──AES-256-GCM ciphertext──▶  server  ──route──▶  client B only
                                         (server never decrypts)
```

---

## Security Model

### Transport Layer
All data travels over **TLS 1.2+** using a 2048-bit RSA self-signed certificate generated at install time. The certificate is accepted by clients with `rejectUnauthorized: false` — traffic is still encrypted, but certificate authenticity is not verified against a CA. For production use, replace the self-signed cert with one issued by a trusted CA.

### End-to-End Encryption
Each client generates a fresh **32-byte random session key** on startup. This key is shared with other clients via `key_announce` messages routed through the server. Private messages (`/pm`) are then encrypted **client-side** with **AES-256-GCM** before being sent:

```
Sender:     plaintext  →  AES-256-GCM(key=senderSessionKey)  →  ciphertext  →  server  →  recipient
Recipient:  ciphertext  →  AES-256-GCM decrypt(key=senderSessionKey)  →  plaintext
```

The server only ever sees the ciphertext. A compromised server cannot read private messages.

### Admin Password
The default admin password is `admin123` (stored as a SHA-256 hash). **Change it before deploying:**

```js
// server.js, line ~25
const ADMIN_PASSWORD_HASH = crypto.createHash('sha256').update('YOUR_PASSWORD').digest('hex');
```

---

## Requirements

- **Node.js** >= 18
- **OpenSSL** available on your system PATH (used to generate the TLS certificate)

To check:
```bash
node --version   # should be v18.x or higher
openssl version  # should print a version string
```

---

## Installation

### From a local clone

```bash
git clone https://github.com/Tomm8y/Terminal-chat.git
cd terminal-chat
npm install        # automatically generates TLS certificate via postinstall.js
```


### Global install (run from anywhere)

```bash
npm install -g .
terminal-chat
```

After `npm install`, you will find `lib/server.key` and `lib/server.crt` generated automatically.

### Binary install (run from the binary file without installing any dependencies)

1. Download the binary file:
```bash
wget https://github.com/owl-sp/Terminal-chat/releases/download/Terminal-chat/terminal-chat
```

2. Make it executable and run:
```bash
chmod +x terminal-chat
./terminal-chat
```

---

## Usage

Run the CLI entry-point:

```bash
# If installed globally:
terminal-chat

# Or directly:
node bin/terminal-chat.js
```

You will be presented with:

```
   ,_,        TERMINAL CHAT 🔐
  (O,O)
  (   )
   " "

Select what you want:
[1] Create chat server
[2] Connect to chat
[3] Stop chat server
>
```

---

### 1. Starting a Server

Choose `[1]` and enter a port (default: **1599**).

```
> 1
Enter port to run chat server (default 1599): 4242
Server started in background on port 4242 (PID 83421).
```

The server runs **detached** in the background. You can close the terminal — the server keeps running.  
Its PID is saved to `~/.terminal-chat/pids/server-4242.pid`.

---

### 2. Connecting as a Client

Choose `[2]` and provide the server details:

```
> 2
Enter server IP: 192.168.1.10
Enter server port: 4242
Enter your name: Alice
Connected to server
Welcome Alice! Your ID is [KJ83]
>
```

Your 4-character **ID** (e.g. `KJ83`) is randomly generated each session. Share it with others so they can send you private messages.

Type any message and press **Enter** to broadcast it to everyone:

```
> Hello everyone!
<Alice> Hello everyone!
```

---

### 3. Stopping a Server

Choose `[3]` and enter the port of the server to stop:

```
> 3
Enter port of server to stop (default 1599): 4242
Server on port 4242 (PID 83421) stopped.
```

---

## In-Chat Commands

Once connected, the following slash-commands are available to all users:

| Command | Description |
|---|---|
| `/help` | Show all available commands |
| `/users` | List online users with their IDs and roles |
| `/pm <ID> <message>` | Send an end-to-end encrypted private message |
| `/admin` | Prompt for admin password to elevate your role |
| `/ping` | Check if you're still connected to the server |
| `/exit` or `/quit` | Disconnect from the server |

Admin-only commands:

| Command | Description |
|---|---|
| `/ban <ID>` | Immediately disconnect a user and block future reconnects |

---

## Private Messaging

Use `/pm` followed by the recipient's ID and your message:

```
> /pm KJ83 Hey Alice, this is a secret message!
[PRIVATE] To KJ83: Hey Alice, this is a secret message!
```

The recipient sees:

```
[PRIVATE] From Bob: Hey Alice, this is a secret message!
```

The message is **AES-256-GCM encrypted** before leaving your machine. The server routes the ciphertext without ever being able to read it.

---

## Admin Controls

To gain admin access:

```
> /admin
Enter admin password:
> admin123
Admin access granted
```

Once admin, you can ban a user:

```
> /users
Online users (3):
- [KJ83] Alice
- [BZ12] Bob (admin)
- [XQ55] Mallory

> /ban XQ55
<announce> User Mallory was banned
```

Mallory is immediately disconnected and will see `You are banned` if they try to reconnect with the same ID.

---

## Project Structure

```
terminal-chat/
├── bin/
│   ├── terminal-chat.js   # CLI entry-point; menu, server spawning, client launching
│   └── postinstall.js     # Generates TLS key+cert with OpenSSL after npm install
├── lib/
│   ├── server.js          # TLS chat server: routing, broadcasting, admin, keep-alive
│   ├── client.js          # TLS chat client: E2E encryption, readline UI, PING/PONG
│   ├── server.key         # (generated) TLS private key — keep this secret!
│   └── server.crt         # (generated) TLS self-signed certificate
└── package.json
```

> **Note:** `server.key` and `server.crt` are created by `postinstall.js` and should **not** be committed to version control. Add them to `.gitignore`:
> ```
> lib/server.key
> lib/server.crt
> ```

---

## Known Limitations

- **Self-signed certificate** — clients skip CA verification (`rejectUnauthorized: false`). Susceptible to MITM attacks on untrusted networks. For production, use a CA-signed certificate.
- **In-memory ban list** — bans are lost when the server restarts.
- **Session keys are not authenticated** — a malicious server could substitute a user's public key in `key_announce` messages (MITM on E2E keys). For stronger guarantees, add out-of-band key fingerprint verification.
- **No message history** — messages are not stored; joining users see only new messages.
- **Single-room** — there is no concept of channels or rooms.

---

## License

MIT © Tommy
