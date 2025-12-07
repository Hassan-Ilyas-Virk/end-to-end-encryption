/**
 * Cryptographic Utilities using Web Crypto API
 * Implements RSA, ECDH, ECDSA, and AES-GCM encryption
 * Works in both browser and Node.js environments
 */

// Detect environment and get appropriate crypto object
const isBrowser = typeof window !== 'undefined';
const crypto = isBrowser ? window.crypto : (await import('crypto')).webcrypto;

// ==================== KEY GENERATION ====================

/**
 * Generate ECDH key pair for key exchange (P-384 curve)
 * @returns {Promise<CryptoKeyPair>} ECDH key pair
 */
export async function generateECDHKeyPair() {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-384', // Using P-384 as required
      },
      true, // extractable
      ['deriveBits', 'deriveKey']
    );
    return keyPair;
  } catch (error) {
    console.error('Error generating ECDH key pair:', error);
    throw error;
  }
}

/**
 * Generate ECDSA key pair for digital signatures (P-384 curve)
 * @returns {Promise<CryptoKeyPair>} ECDSA key pair
 */
export async function generateECDSAKeyPair() {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
      true, // extractable
      ['sign', 'verify']
    );
    return keyPair;
  } catch (error) {
    console.error('Error generating ECDSA key pair:', error);
    throw error;
  }
}

// ==================== KEY IMPORT/EXPORT ====================

/**
 * Export public key to base64 string
 * @param {CryptoKey} publicKey - Public key to export
 * @returns {Promise<string>} Base64 encoded public key
 */
export async function exportPublicKey(publicKey) {
  try {
    const exported = await crypto.subtle.exportKey('spki', publicKey);
    return arrayBufferToBase64(exported);
  } catch (error) {
    console.error('Error exporting public key:', error);
    throw error;
  }
}

/**
 * Export private key to base64 string
 * @param {CryptoKey} privateKey - Private key to export
 * @returns {Promise<string>} Base64 encoded private key
 */
export async function exportPrivateKey(privateKey) {
  try {
    const exported = await crypto.subtle.exportKey('pkcs8', privateKey);
    return arrayBufferToBase64(exported);
  } catch (error) {
    console.error('Error exporting private key:', error);
    throw error;
  }
}

/**
 * Import ECDH public key from base64 string
 * @param {string} base64Key - Base64 encoded public key
 * @returns {Promise<CryptoKey>} Imported public key
 */
export async function importECDHPublicKey(base64Key) {
  try {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'ECDH',
        namedCurve: 'P-384',
      },
      true,
      []
    );
  } catch (error) {
    console.error('Error importing ECDH public key:', error);
    throw error;
  }
}

/**
 * Import ECDH private key from base64 string
 * @param {string} base64Key - Base64 encoded private key
 * @returns {Promise<CryptoKey>} Imported private key
 */
export async function importECDHPrivateKey(base64Key) {
  try {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'ECDH',
        namedCurve: 'P-384',
      },
      true,
      ['deriveBits', 'deriveKey']
    );
  } catch (error) {
    console.error('Error importing ECDH private key:', error);
    throw error;
  }
}

/**
 * Import ECDSA public key from base64 string
 * @param {string} base64Key - Base64 encoded public key
 * @returns {Promise<CryptoKey>} Imported public key
 */
export async function importECDSAPublicKey(base64Key) {
  try {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
      true,
      ['verify']
    );
  } catch (error) {
    console.error('Error importing ECDSA public key:', error);
    throw error;
  }
}

/**
 * Import ECDSA private key from base64 string
 * @param {string} base64Key - Base64 encoded private key
 * @returns {Promise<CryptoKey>} Imported private key
 */
export async function importECDSAPrivateKey(base64Key) {
  try {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
      true,
      ['sign']
    );
  } catch (error) {
    console.error('Error importing ECDSA private key:', error);
    throw error;
  }
}

// ==================== KEY DERIVATION (ECDH) ====================

/**
 * Derive shared secret using ECDH
 * @param {CryptoKey} privateKey - Own private key
 * @param {CryptoKey} publicKey - Other party's public key
 * @returns {Promise<ArrayBuffer>} Derived shared secret bits
 */
export async function deriveSharedSecret(privateKey, publicKey) {
  try {
    const sharedBits = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: publicKey,
      },
      privateKey,
      384 // P-384 curve produces 384 bits
    );
    return sharedBits;
  } catch (error) {
    console.error('Error deriving shared secret:', error);
    throw error;
  }
}

/**
 * Derive AES-GCM session key from shared secret using HKDF
 * @param {ArrayBuffer} sharedSecret - Shared secret from ECDH
 * @param {string} salt - Salt value (should be unique per session)
 * @returns {Promise<CryptoKey>} AES-GCM key
 */
export async function deriveSessionKey(sharedSecret, salt) {
  try {
    // Import shared secret as raw key material
    const sharedKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    // Derive AES-GCM key using HKDF
    const sessionKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: stringToArrayBuffer(salt),
        info: stringToArrayBuffer('session-key-derivation'),
      },
      sharedKey,
      { name: 'AES-GCM', length: 256 },
      false, // not extractable for security
      ['encrypt', 'decrypt']
    );

    return sessionKey;
  } catch (error) {
    console.error('Error deriving session key:', error);
    throw error;
  }
}

// ==================== DIGITAL SIGNATURES ====================

/**
 * Sign data using ECDSA private key
 * @param {CryptoKey} privateKey - ECDSA private key
 * @param {string} data - Data to sign
 * @returns {Promise<string>} Base64 encoded signature
 */
export async function signData(privateKey, data) {
  try {
    const dataBuffer = stringToArrayBuffer(data);
    const signature = await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-384' },
      },
      privateKey,
      dataBuffer
    );
    return arrayBufferToBase64(signature);
  } catch (error) {
    console.error('Error signing data:', error);
    throw error;
  }
}

/**
 * Verify signature using ECDSA public key
 * @param {CryptoKey} publicKey - ECDSA public key
 * @param {string} signature - Base64 encoded signature
 * @param {string} data - Original data
 * @returns {Promise<boolean>} True if signature is valid
 */
export async function verifySignature(publicKey, signature, data) {
  try {
    const signatureBuffer = base64ToArrayBuffer(signature);
    const dataBuffer = stringToArrayBuffer(data);

    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-384' },
      },
      publicKey,
      signatureBuffer,
      dataBuffer
    );

    return isValid;
  } catch (error) {
    console.error('Error verifying signature:', error);
    return false;
  }
}

// ==================== AES-GCM ENCRYPTION/DECRYPTION ====================

/**
 * Encrypt data using AES-256-GCM
 * @param {CryptoKey} key - AES-GCM key
 * @param {string} plaintext - Data to encrypt
 * @param {ArrayBuffer} iv - Initialization vector (must be 12 bytes for GCM)
 * @returns {Promise<{ciphertext: string, authTag: string}>} Encrypted data and auth tag
 */
export async function encryptAES(key, plaintext, iv) {
  try {
    const plaintextBuffer = stringToArrayBuffer(plaintext);

    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128, // 128-bit authentication tag
      },
      key,
      plaintextBuffer
    );

    // AES-GCM returns ciphertext + auth tag concatenated
    // Last 16 bytes are the auth tag
    const ciphertextLength = encrypted.byteLength - 16;
    const ciphertext = encrypted.slice(0, ciphertextLength);
    const authTag = encrypted.slice(ciphertextLength);

    return {
      ciphertext: arrayBufferToBase64(ciphertext),
      authTag: arrayBufferToBase64(authTag),
    };
  } catch (error) {
    console.error('Error encrypting with AES-GCM:', error);
    throw error;
  }
}

/**
 * Decrypt data using AES-256-GCM
 * @param {CryptoKey} key - AES-GCM key
 * @param {string} ciphertext - Base64 encoded ciphertext
 * @param {string} authTag - Base64 encoded authentication tag
 * @param {ArrayBuffer} iv - Initialization vector
 * @returns {Promise<string>} Decrypted plaintext
 */
export async function decryptAES(key, ciphertext, authTag, iv) {
  try {
    const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
    const authTagBuffer = base64ToArrayBuffer(authTag);

    // Concatenate ciphertext and auth tag for Web Crypto API
    const combined = new Uint8Array(ciphertextBuffer.byteLength + authTagBuffer.byteLength);
    combined.set(new Uint8Array(ciphertextBuffer), 0);
    combined.set(new Uint8Array(authTagBuffer), ciphertextBuffer.byteLength);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      key,
      combined.buffer
    );

    return arrayBufferToString(decrypted);
  } catch (error) {
    console.error('Error decrypting with AES-GCM:', error);
    throw error;
  }
}

// ==================== SYMMETRIC KEY GENERATION ====================

/**
 * Generate a random AES-256-GCM key
 * @returns {Promise<CryptoKey>} AES-GCM key
 */
export async function generateAESKey() {
  try {
    const key = await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256,
      },
      true, // extractable
      ['encrypt', 'decrypt']
    );
    return key;
  } catch (error) {
    console.error('Error generating AES key:', error);
    throw error;
  }
}

/**
 * Export AES key to base64 string
 * @param {CryptoKey} key - AES key to export
 * @returns {Promise<string>} Base64 encoded key
 */
export async function exportAESKey(key) {
  try {
    const exported = await crypto.subtle.exportKey('raw', key);
    return arrayBufferToBase64(exported);
  } catch (error) {
    console.error('Error exporting AES key:', error);
    throw error;
  }
}

/**
 * Import AES key from base64 string
 * @param {string} base64Key - Base64 encoded key
 * @returns {Promise<CryptoKey>} Imported AES key
 */
export async function importAESKey(base64Key) {
  try {
    const keyData = base64ToArrayBuffer(base64Key);
    return await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'AES-GCM' },
      true,
      ['encrypt', 'decrypt']
    );
  } catch (error) {
    console.error('Error importing AES key:', error);
    throw error;
  }
}

// ==================== RANDOM DATA GENERATION ====================

/**
 * Generate cryptographically secure random bytes
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} Random bytes
 */
export function generateRandomBytes(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

/**
 * Generate a random nonce (32 bytes)
 * @returns {string} Base64 encoded nonce
 */
export function generateNonce() {
  const nonce = generateRandomBytes(32);
  return arrayBufferToBase64(nonce.buffer);
}

/**
 * Generate a random IV for AES-GCM (12 bytes as recommended)
 * @returns {ArrayBuffer} IV
 */
export function generateIV() {
  return generateRandomBytes(12).buffer;
}

/**
 * Generate a random salt (32 bytes)
 * @returns {string} Random salt string
 */
export function generateSalt() {
  const salt = generateRandomBytes(32);
  return arrayBufferToBase64(salt.buffer);
}

// ==================== HASHING ====================

/**
 * Hash data using SHA-256
 * @param {string} data - Data to hash
 * @returns {Promise<string>} Base64 encoded hash
 */
export async function hashSHA256(data) {
  try {
    const dataBuffer = stringToArrayBuffer(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    return arrayBufferToBase64(hashBuffer);
  } catch (error) {
    console.error('Error hashing data:', error);
    throw error;
  }
}

// ==================== UTILITY FUNCTIONS ====================

/**
 * Convert ArrayBuffer to Base64 string
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} Base64 string
 */
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 * @param {string} base64 - Base64 string
 * @returns {ArrayBuffer} ArrayBuffer
 */
export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert string to ArrayBuffer
 * @param {string} str - String to convert
 * @returns {ArrayBuffer} ArrayBuffer
 */
export function stringToArrayBuffer(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str).buffer;
}

/**
 * Convert ArrayBuffer to string
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} String
 */
export function arrayBufferToString(buffer) {
  const decoder = new TextDecoder();
  return decoder.decode(buffer);
}

/**
 * Convert ArrayBuffer to hex string (for debugging)
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} Hex string
 */
export function arrayBufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

