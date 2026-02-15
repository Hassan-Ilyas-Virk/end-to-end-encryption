# Secure Chat Application

A secure, real-time messaging application built with a focus on privacy and security. It features **End-to-End Encryption (E2EE)**, digital signatures, and protection against common cryptographic attacks.

![Security Status](https://img.shields.io/badge/Security-E2EE-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue)

## 🌟 Key Features

### 🔒 Security & Privacy
*   **End-to-End Encryption (E2EE):** Messages are encrypted on the sender's device and only decrypted on the recipient's device. The server never sees the plaintext.
*   **Elliptic Curve Cryptography:**
    *   **ECDH (P-384):** Secure key exchange for generating shared secrets.
    *   **ECDSA (P-384):** Digital signatures to verify message authenticity and integrity.
*   **AES-256-GCM:** Authenticated symmetric encryption for messages and files.
*   **Forward Secrecy:** Unique session keys per conversation.
*   **Local Key Storage:** Private keys are stored securely in the browser's IndexedDB and never leave your device.

### 🛡️ Threat Mitigation
*   **Man-in-the-Middle (MITM) Protection:** Digital signatures prevent attackers from intercepting and modifying keys during exchange.
*   **Replay Attack Protection:**
    *   **Nonces:** Unique identifiers for every message.
    *   **Timestamps:** Strict 5-minute window for message validity.
    *   **Sequence Numbers:** Ensures correct message ordering.
*   **Tamper Resistance:** Authenticated encryption (GCM) ensures message integrity.

### 🚀 Modern Experience
*   **Secure File Sharing:** Encrypted file uploads and downloads.
*   **User Authentication:** Secure signup and login with email verification support.
*   **Responsive UI:** Modern interface transparency effects (Glassmorphism).

---

## 🛠️ Technology Stack

*   **Frontend:** React, Vite, TailwindCSS (inferred/custom CSS)
*   **Backend:** Node.js, Express.js
*   **Database:** MongoDB
*   **Cryptography:** Web Crypto API (Native browser implementation)

---

## 🚀 Getting Started

### Prerequisites
*   Node.js (v16 or higher)
*   MongoDB (Local or Atlas URI)

### Installation

1.  **Clone the repository**
    ```bash
    git clone <repository-url>
    cd secure-chat
    ```

2.  **Install dependencies**
    ```bash
    npm install
    ```

3.  **Environment Setup**
    Create a `.env` file in the root directory:
    ```env
    PORT=3001
    MONGODB_URI=your_mongodb_connection_string
    JWT_SECRET=your_jwt_secret_key
    ```
    *(Note: Refer to `.env.example` if available)*

### Running the Application

1.  **Start the Backend Server**
    ```bash
    npm run server
    ```
    Runs on `http://localhost:3001`

2.  **Start the Frontend**
    ```bash
    npm run dev
    ```
    Runs on `http://localhost:5173`

3.  **Run Both Concurrently**
    ```bash
    npm run dev:all
    ```

---

## 🧪 Security Demonstrations

This project includes scripts to demonstrate and verify security mechanisms.

### 1. MITM Attack Demo
Simulates a Man-in-the-Middle attack on the key exchange protocol.
```bash
node src/attacks/mitmAttack.js
```
*   **Scenario 1:** Unsigned ECDH (Vulnerable) - Attacker intercepts keys.
*   **Scenario 2:** Signed ECDH (Secure) - Attack blocked by signature verification.

### 2. Replay Attack Demo
Tests the system's resilience against replayed messages.
```bash
node src/attacks/replayAttack.js
```
*   Verifies protection against duplicate nonces, old timestamps, and out-of-order messages.

See [src/attacks/README.md](src/attacks/README.md) for more details.

---

## 📚 Documentation
*   **[Threat Model](THREAT_MODELING.md):** Detailed STRIDE analysis of potential threats and mitigations.
*   **[Cryptographic Concepts](concepts.md):** Explanation of the crypto primitives (ECDH, ECDSA, AES-GCM) used in the app.

---

## ⚠️ Important Notes
*   **Key Storage:** Clearing your browser data (IndexedDB) will result in the loss of your private keys and inability to decrypt past messages.
*   **Disclaimer:** This is an educational project demonstrating secure messaging concepts.

## License
MIT
