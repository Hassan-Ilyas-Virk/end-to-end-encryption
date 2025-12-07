# Cryptographic Concepts & Terms

## Core Algorithms

### 1. ECDH (Elliptic Curve Diffie-Hellman)
*   **Purpose:** **Key Exchange** (Confidentiality).
*   **Function:** Allows two users to mathematically derive a shared secret session key without ever sending it over the network.
*   **Role in App:** Used to generate the `Session Key` that encrypts messages.

### 2. ECDSA (Elliptic Curve Digital Signature Algorithm)
*   **Purpose:** **Digital Signatures** (Integrity & Authenticity).
*   **Function:** Uses a private key to "sign" data. Anyone with the public key can verify it came from you and wasn't changed.
*   **Role in App:** Authenticates messages to prevent tampering and Man-in-the-Middle attacks.

### 3. AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)
*   **Purpose:** **Symmetric Encryption**.
*   **Function:** Uses the shared Session Key to encrypt the actual message text and files.
*   **GCM Mode:** Adds an "integrity check" (tag) to ensure the encrypted data hasn't been modified.

### 4. EC (Elliptic Curve)
*   **Definition:** A type of cryptography based on the math of curves (`y² = x³ + ax + b`).
*   **Benefit:** Provides the same security as older systems (like RSA) but with much **smaller keys** and **faster performance**.
*   **Curve Used:** `P-384` (NIST standard, high security).

---

## Security Terms

### 5. Nonce (Number Used Once)
*   **Definition:** A random number generated for a specific message or session.
*   **Purpose:** Ensures every encrypted message looks different, even if the text is the same.
*   **Critical For:** Preventing **Replay Attacks**.

### 6. Forward Secrecy
*   **Definition:** A property where compromising today's keys doesn't compromise past messages.
*   **Implementation:** When you generate new keys (e.g., on a new device), old private keys are gone, making old messages permanently undecryptable.

### 7. Session Timeout
*   **Definition:** A security limit on how long a handshake request is valid.
*   **Implementation:** The system rejects any handshake message with a timestamp older than **5 minutes** (300,000 ms) or with a future timestamp.
*   **Purpose:** Prevents attackers from replaying old, captured handshake attempts.

---

## Implementation Details

### 8. Where Encryption Happens (Client-Side)
*   **Location:** **Entirely in the Browser**.
*   **Process:**
    1.  **Sending:** Text is encrypted & signed on your device → Sent to Server.
    2.  **Receiving:** Encrypted text is downloaded → Decrypted & verified on your device.
*   **Server Role:** The server (MongoDB) **only stores encrypted gibberish**. It never sees the real message or the private keys.

### 9. Custom vs. Standard Protocols
*   **Standard Primitives:** We use standard math for keys (`P-384` curve) and encryption (`AES-GCM`).
*   **Custom Protocol:** The **Key Exchange Logic** (how we combine keys, use salts, and order user IDs) is custom to this application.
    *   *Example:* We manually create a salt string like `salt-{user1}-{user2}` before deriving the session key.

### 10. File Chunking (Large Files)
*   **Current State:** The app currently encrypts files as **one single block**.
*   **Ideal Implementation:** Large files should be split into smaller pieces (e.g., 1MB chunks).
    *   Each chunk gets its own unique IV.
    *   Chunks are encrypted and uploaded separately.
    *   This prevents memory crashes and allows resuming failed uploads.

---

## Attacks & Defenses

### 11. MITM (Man-in-the-Middle) Attack
*   **The Attack:** An attacker sits between two users, intercepting and modifying messages.
*   **Defense:** **ECDSA Signatures**. The attacker cannot sign fake messages because they don't have the user's private key.

### 12. Replay Attack
*   **The Attack:** An attacker records a valid message/handshake and sends it again later to repeat an action.
*   **Defense:** **Nonces + Timestamps**. The server rejects messages with used nonces or old timestamps (> 5 mins).

---

## Key Management

### 9. The 4 Keys (Per User)
Every user has **2 Key Pairs** (4 keys total):

| Key Name | Type | Location | Purpose |
|----------|------|----------|---------|
| **ECDH Private** | Private | Browser (IndexedDB) | Decrypting incoming messages |
| **ECDH Public** | Public | Server | Others use it to encrypt for you |
| **ECDSA Private** | Private | Browser (IndexedDB) | Signing your outgoing messages |
| **ECDSA Public** | Public | Server | Others use it to verify your signatures |
