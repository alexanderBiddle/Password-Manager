# 🔐 CipherSafe  
### Zero-Knowledge Secure Password Vault with a Custom Four-Way Handshake Protocol

---

## 📌 Overview

**CipherSafe** is a **security-first, zero-knowledge password vault** designed and implemented as a full-stack cybersecurity capstone project.  
The system demonstrates **advanced applied cryptography**, **secure protocol design**, **defensive programming**, and **secure software engineering principles** typically found in professional security products.

Unlike traditional password managers, CipherSafe:
- **Never stores or processes plaintext secrets on the server**
- Uses **client-side cryptography exclusively**
- Implements a **custom Four-Way Handshake protocol** layered on **TLS 1.3**
- Enforces **strict validation, replay protection, session binding, and cryptographic integrity checks** at every stage

This repository contains **the complete client and server implementation**, database schema logic, cryptographic managers, and validation layers.

> 🎯 **Goal:**  
> Build a realistic, auditable, and defensively designed secure system that demonstrates real-world cryptographic engineering and protocol design skills to future employers.

---

## 🧠 Core Security Principles

CipherSafe was engineered around the following security guarantees:

- **Zero-Knowledge Architecture**
  - The server never sees:
    - User passwords
    - Vault contents
    - Encryption keys
- **End-to-End Encryption**
  - All sensitive data is encrypted **before** leaving the client
- **Cryptographic Key Isolation**
  - Distinct keys for authentication, sessions, vault encryption
- **Defense-in-Depth**
  - Validation, integrity checks, signatures, replay protection
- **Explicit Threat Modeling**
  - Man-in-the-middle, replay, tampering, brute force, and session hijacking considered

---

## 🔐 Cryptography Stack

CipherSafe uses modern, well-vetted cryptographic primitives:

| Purpose | Algorithm |
|------|---------|
| Password hashing | **Argon2id** |
| Vault encryption | **AES-256-GCM** |
| Session encryption | **AES-256-GCM** |
| Key exchange | **RSA-2048 (OAEP-SHA256)** |
| Digital signatures | **RSA-PSS (SHA-256)** |
| Integrity checks | **SHA-256** |
| Transport | **TLS 1.3** |
| Key derivation | **HKDF-SHA256** |

All cryptographic operations follow **explicit size checks**, **format validation**, and **strict encoding rules (Base64URL)**.

---

## 🔁 Custom Four-Way Handshake Protocol

CipherSafe does **not** rely on default session cookies or opaque auth tokens.  
Instead, it implements a **custom cryptographic handshake** designed for learning, auditing, and correctness.

### Handshake Flow

1. **Client Hello**
   - Sends:
     - Protocol version
     - Username
     - Client RSA public key
     - Timestamp (ISO-8601Z)
     - SHA_256 checksum

2. **Server Hello**
   - Returns:
     - Server RSA public key
     - RSA-encrypted AES-256 session key
     - Key identifier & expiry
     - Digital signature
     - Encrypted payload

3. **Client Encrypted Request**
   - Sends:
     - AES-encrypted request data
     - Session-bound checksum
     - Nonce (replay protection)

4. **Server Encrypted Response**
   - Returns:
     - AES-encrypted response
     - Digital signature
     - Integrity checksum

### Security Properties

- Mutual authentication
- Session key confidentiality
- Replay protection (nonce tracking)
- Explicit protocol version enforcement
- Strong binding between identity and session

---

## 🗄️ Vault Data Model

- Each user has **isolated vault tables**
- Vault entries are stored as:
  - Encrypted website
  - Encrypted username
  - Encrypted email
  - Encrypted password
- The server **never decrypts vault fields**
- Vault operations supported:
  - Fetch all accounts
  - Fetch single password
  - Add account
  - Update account
  - Delete account
  - Rotate master password + re-encrypt vault

---

## 🧱 Project Architecture
```text
+----------------------------------------------------------------------------------+
|                              Browser (Client)                                    |
|                                                                                  |
|  - Argon2id password derivation                                                  |
|  - AES-256-GCM vault encryption                                                  |
|  - RSA-2048 key generation                                                       |
|  - Four-Way Handshake client logic                                               |
+-------------------------------------+--------------------------------------------+
                                      |
                                      |  TLS 1.3 (HTTPS)
                                      v
+----------------------------------------------------------------------------------+
|                         Flask API Server (Python)                                |
|                           (Apache + mod_wsgi)                                    |
|                                                                                  |
|  +---------------------+     +---------------------+     +--------------------+  |
|  | Handshake Handler   | --> | Session Manager     | --> | Validation Layer   |  |
|  | - Protocol steps    |     | - AES session keys  |     | - Schema checks    |  |
|  | - RSA verification  |     | - TTL enforcement   |     | - Base64URL rules  |  |
|  +---------------------+     | - Nonce replay prot |     +--------------------+  |
|                              +---------------------+                             |
|                                                                                  |
|  +-------------------------------------------------------------------------+     |
|  | Vault Handler                                                           |     |
|  | - Stores opaque ciphertext only                                         |     |
|  | - Never decrypts user data                                              |     |
|  +-------------------------------------------------------------------------+     |
+-------------------------------------+--------------------------------------------+
                                      |
                                      v
+----------------------------------------------------------------------------------+
|                         PostgreSQL Database                                      |
|                                                                                  |
|  - Encrypted vault fields only                                                   |
|  - No plaintext credentials                                                      |
|  - No encryption keys                                                            |
+----------------------------------------------------------------------------------+
```

This architecture enforces a **strict separation of responsibilities**:
- All cryptographic operations occur on the **client**
- The server acts as a **validated, authenticated, encrypted relay**
- The database stores **only opaque ciphertext**

---

## 🚀 Running the Project

### ✅ Prerequisites

- Python **3.10+**
- PostgreSQL **14+**
- Apache with **mod_wsgi**
- OpenSSL
- Modern browser (Chrome / Firefox / Edge)

---

### 📥 Clone the Repository

```bash
git clone https://github.com/your-username/cipherSafe.git
cd cipherSafe
