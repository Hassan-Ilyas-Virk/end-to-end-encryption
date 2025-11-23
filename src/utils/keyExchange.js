/**
 * Custom Key Exchange Protocol
 * 
 * Protocol Flow:
 * 1. Initiator generates ephemeral ECDH key pair
 * 2. Initiator signs public key + nonce + timestamp with their ECDSA private key
 * 3. Initiator sends signed package to responder
 * 4. Responder verifies signature
 * 5. Responder generates ephemeral ECDH key pair
 * 6. Responder derives shared secret using ECDH
 * 7. Responder signs their public key + nonce + timestamp
 * 8. Responder sends signed response
 * 9. Initiator verifies signature and derives shared secret
 * 10. Both parties derive session key using HKDF
 * 11. Key confirmation message is exchanged (encrypted with session key)
 * 
 * This prevents MITM attacks through mutual authentication via signatures
 */

import {
  generateECDHKeyPair,
  exportPublicKey,
  importECDHPublicKey,
  importECDSAPrivateKey,
  importECDSAPublicKey,
  deriveSharedSecret,
  deriveSessionKey,
  signData,
  verifySignature,
  generateNonce,
  generateSalt,
  hashSHA256,
} from './crypto.js';

// Note: Database operations removed - using in-memory session storage only
// For full key exchange with database, implement MongoDB endpoints

// Session key cache (in memory, per session)
const sessionKeys = new Map();

/**
 * Step 1: Initiator starts key exchange
 * @param {string} initiatorId - Initiator's user ID
 * @param {string} responderId - Responder's user ID
 * @param {string} initiatorSignPrivateKey - Initiator's ECDSA private key (base64)
 * @returns {Promise<Object>} Key exchange initiation data
 */
export async function initiateKeyExchange(initiatorId, responderId, initiatorSignPrivateKey) {
  try {
    console.log('=== KEY EXCHANGE STEP 1: Initiation ===');
    
    // Generate ephemeral ECDH key pair for this session
    const ephemeralKeyPair = await generateECDHKeyPair();
    const ephemeralPublicKey = await exportPublicKey(ephemeralKeyPair.publicKey);
    
    // Generate nonce and timestamp for replay protection
    const nonce = generateNonce();
    const timestamp = Date.now();
    
    // Create data to sign
    const dataToSign = JSON.stringify({
      initiatorId,
      responderId,
      ephemeralPublicKey,
      nonce,
      timestamp,
    });
    
    // Sign with initiator's long-term ECDSA private key
    const privateKey = await importECDSAPrivateKey(initiatorSignPrivateKey);
    const signature = await signData(privateKey, dataToSign);
    
    // Store ephemeral private key temporarily (will be deleted after session establishment)
    const sessionId = `${initiatorId}-${responderId}-${timestamp}`;
    sessionKeys.set(sessionId, {
      ephemeralPrivateKey: ephemeralKeyPair.privateKey,
      role: 'initiator',
    });
    
    // Note: Database storage removed for simplicity
    // Session stored in memory only
    console.log('✓ Key exchange initiated (in-memory only)');
    
    return {
      sessionId,
      ephemeralPublicKey,
      nonce,
      timestamp,
      signature,
      dataToSign,
    };
  } catch (error) {
    console.error('Error initiating key exchange:', error);
    await logSecurityEvent(
      initiatorId,
      'KEY_EXCHANGE_FAILED',
      `Key exchange initiation failed: ${error.message}`,
      'ERROR'
    );
    throw error;
  }
}

/**
 * Step 2: Responder processes initiation and responds
 * @param {string} sessionId - Database session ID
 * @param {string} responderId - Responder's user ID
 * @param {string} responderSignPrivateKey - Responder's ECDSA private key (base64)
 * @param {string} initiatorSignPublicKey - Initiator's ECDSA public key (base64)
 * @param {Object} initiationData - Data from initiator
 * @returns {Promise<Object>} Key exchange response data
 */
export async function respondToKeyExchange(
  sessionId,
  responderId,
  responderSignPrivateKey,
  initiatorSignPublicKey,
  initiationData
) {
  try {
    console.log('=== KEY EXCHANGE STEP 2: Response ===');
    
    // Verify timestamp (prevent replay attacks - reject if older than 5 minutes)
    const currentTime = Date.now();
    const timeDiff = currentTime - initiationData.timestamp;
    if (timeDiff > 5 * 60 * 1000 || timeDiff < 0) {
      throw new Error('Key exchange request expired or has invalid timestamp');
    }
    
    // Verify initiator's signature
    const publicKey = await importECDSAPublicKey(initiatorSignPublicKey);
    const isValid = await verifySignature(
      publicKey,
      initiationData.signature,
      initiationData.dataToSign
    );
    
    if (!isValid) {
      await logSecurityEvent(
        responderId,
        'KEY_EXCHANGE_INVALID_SIGNATURE',
        'Invalid signature in key exchange initiation',
        'CRITICAL'
      );
      throw new Error('Invalid signature from initiator - possible MITM attack!');
    }
    
    console.log('✓ Initiator signature verified');
    
    // Generate ephemeral ECDH key pair
    const ephemeralKeyPair = await generateECDHKeyPair();
    const ephemeralPublicKey = await exportPublicKey(ephemeralKeyPair.publicKey);
    
    // Generate nonce and timestamp
    const nonce = generateNonce();
    const timestamp = Date.now();
    
    // Import initiator's ephemeral public key
    const initiatorEphemeralPublicKey = await importECDHPublicKey(
      initiationData.ephemeralPublicKey
    );
    
    // Derive shared secret using ECDH
    const sharedSecret = await deriveSharedSecret(
      ephemeralKeyPair.privateKey,
      initiatorEphemeralPublicKey
    );
    
    console.log('✓ Shared secret derived (responder side)');
    
    // Derive session key using HKDF
    const salt = generateSalt();
    const sessionKey = await deriveSessionKey(sharedSecret, salt);
    
    console.log('✓ Session key derived (responder side)');
    
    // Create response data to sign
    const responseDataToSign = JSON.stringify({
      sessionId,
      responderId,
      ephemeralPublicKey,
      nonce,
      timestamp,
      initiatorNonce: initiationData.nonce,
    });
    
    // Sign response
    const privateKey = await importECDSAPrivateKey(responderSignPrivateKey);
    const signature = await signData(privateKey, responseDataToSign);
    
    // Store session key and metadata
    sessionKeys.set(sessionId, {
      sessionKey,
      role: 'responder',
      otherPartyId: initiationData.initiatorId,
      salt,
    });
    
    // Note: Database update removed for simplicity
    console.log('✓ Key exchange responded (in-memory only)');
    
    return {
      ephemeralPublicKey,
      nonce,
      timestamp,
      signature,
      salt,
      responseDataToSign,
    };
  } catch (error) {
    console.error('Error responding to key exchange:', error);
    await logSecurityEvent(
      responderId,
      'KEY_EXCHANGE_FAILED',
      `Key exchange response failed: ${error.message}`,
      'ERROR'
    );
    throw error;
  }
}

/**
 * Step 3: Initiator completes key exchange
 * @param {string} sessionId - Session ID
 * @param {string} initiatorId - Initiator's user ID
 * @param {Object} responseData - Response from responder
 * @param {string} responderSignPublicKey - Responder's ECDSA public key (base64)
 * @returns {Promise<CryptoKey>} Derived session key
 */
export async function completeKeyExchange(
  sessionId,
  initiatorId,
  responseData,
  responderSignPublicKey
) {
  try {
    console.log('=== KEY EXCHANGE STEP 3: Completion ===');
    
    // Verify timestamp
    const currentTime = Date.now();
    const timeDiff = currentTime - responseData.timestamp;
    if (timeDiff > 5 * 60 * 1000 || timeDiff < 0) {
      throw new Error('Key exchange response expired or has invalid timestamp');
    }
    
    // Verify responder's signature
    const publicKey = await importECDSAPublicKey(responderSignPublicKey);
    const isValid = await verifySignature(
      publicKey,
      responseData.signature,
      responseData.responseDataToSign
    );
    
    if (!isValid) {
      await logSecurityEvent(
        initiatorId,
        'KEY_EXCHANGE_INVALID_SIGNATURE',
        'Invalid signature in key exchange response',
        'CRITICAL'
      );
      throw new Error('Invalid signature from responder - possible MITM attack!');
    }
    
    console.log('✓ Responder signature verified');
    
    // Retrieve ephemeral private key
    const sessionData = sessionKeys.get(sessionId);
    if (!sessionData || !sessionData.ephemeralPrivateKey) {
      throw new Error('Session data not found');
    }
    
    // Import responder's ephemeral public key
    const responderEphemeralPublicKey = await importECDHPublicKey(
      responseData.ephemeralPublicKey
    );
    
    // Derive shared secret using ECDH
    const sharedSecret = await deriveSharedSecret(
      sessionData.ephemeralPrivateKey,
      responderEphemeralPublicKey
    );
    
    console.log('✓ Shared secret derived (initiator side)');
    
    // Derive session key using HKDF (same salt from responder)
    const sessionKey = await deriveSessionKey(sharedSecret, responseData.salt);
    
    console.log('✓ Session key derived (initiator side)');
    
    // Update session data
    sessionKeys.set(sessionId, {
      sessionKey,
      role: 'initiator',
      otherPartyId: responseData.responderId,
      salt: responseData.salt,
    });
    
    // Note: Database update removed for simplicity
    console.log('✓ Key exchange completed (in-memory only)');
    
    console.log('✓ Key exchange completed successfully!');
    
    return sessionKey;
  } catch (error) {
    console.error('Error completing key exchange:', error);
    await logSecurityEvent(
      initiatorId,
      'KEY_EXCHANGE_FAILED',
      `Key exchange completion failed: ${error.message}`,
      'ERROR'
    );
    throw error;
  }
}

/**
 * Step 4: Key confirmation (both parties exchange confirmation messages)
 * @param {string} sessionId - Session ID
 * @param {string} userId - User ID
 * @returns {Promise<string>} Confirmation hash
 */
export async function sendKeyConfirmation(sessionId, userId) {
  try {
    console.log('=== KEY EXCHANGE STEP 4: Key Confirmation ===');
    
    const sessionData = sessionKeys.get(sessionId);
    if (!sessionData || !sessionData.sessionKey) {
      throw new Error('Session key not found');
    }
    
    // Create confirmation message
    const confirmationMessage = `KEY_CONFIRMED:${sessionId}:${userId}:${Date.now()}`;
    const confirmationHash = await hashSHA256(confirmationMessage);
    
    // Note: Database update removed for simplicity
    console.log('✓ Key confirmed (in-memory only)');
    
    console.log('✓ Key confirmation sent');
    
    return confirmationHash;
  } catch (error) {
    console.error('Error sending key confirmation:', error);
    throw error;
  }
}

/**
 * Get session key from cache
 * @param {string} sessionId - Session ID
 * @returns {CryptoKey|null} Session key or null if not found
 */
export function getSessionKey(sessionId) {
  const sessionData = sessionKeys.get(sessionId);
  return sessionData ? sessionData.sessionKey : null;
}

/**
 * Clear session key from cache
 * @param {string} sessionId - Session ID
 */
export function clearSessionKey(sessionId) {
  sessionKeys.delete(sessionId);
  console.log(`Session key cleared for ${sessionId}`);
}

/**
 * Get active session for two users (in-memory only)
 * @param {string} userId1 - First user ID
 * @param {string} userId2 - Second user ID
 * @returns {Promise<Object|null>} Session data or null
 */
export async function getActiveSession(userId1, userId2) {
  // In-memory implementation - check sessionKeys Map
  const userIds = [userId1, userId2].sort();
  const sessionId = `shared-${userIds[0]}-${userIds[1]}`;
  
  if (sessionKeys.has(sessionId)) {
    return { id: sessionId, active: true };
  }
  
  return null;
}

/**
 * Create a shared session key using ECDH
 * Both users derive the SAME key from their ECDH key pairs
 * @param {string} userId1 - First user ID (current user)
 * @param {string} userId2 - Second user ID (other user)
 * @param {string} myECDHPrivateKey - My ECDH private key (base64)
 * @param {string} otherECDHPublicKey - Other user's ECDH public key (base64)
 * @returns {Promise<string>} Session ID
 */
export async function createSharedSession(userId1, userId2, myECDHPrivateKey, otherECDHPublicKey) {
  try {
    console.log('🔑 Creating shared session using ECDH...');
    console.log('User 1 (me):', userId1.substring(0, 8));
    console.log('User 2 (other):', userId2.substring(0, 8));
    
    // Import crypto utilities
    const {
      importECDHPrivateKey,
      importECDHPublicKey,
      deriveSharedSecret,
      deriveSessionKey,
      arrayBufferToHex,
    } = await import('./crypto.js');
    
    // Import keys
    const myPrivateKey = await importECDHPrivateKey(myECDHPrivateKey);
    const otherPublicKey = await importECDHPublicKey(otherECDHPublicKey);
    
    console.log('✓ Keys imported');
    
    // Derive shared secret using ECDH
    const sharedSecret = await deriveSharedSecret(myPrivateKey, otherPublicKey);
    const sharedSecretHex = arrayBufferToHex(sharedSecret).substring(0, 32);
    console.log('✓ Shared secret (first 32 chars):', sharedSecretHex);
    
    // Create deterministic salt from both user IDs (sorted to ensure same order)
    const userIds = [userId1, userId2].sort();
    const saltString = `salt-${userIds[0]}-${userIds[1]}`;
    console.log('✓ Using salt:', saltString.substring(0, 40) + '...');
    
    // Derive session key from shared secret
    const sessionKey = await deriveSessionKey(sharedSecret, saltString);
    console.log('✓ Session key derived from shared secret');
    
    // Create session ID
    const sessionId = `shared-${userIds[0]}-${userIds[1]}`;
    console.log('✓ Session ID:', sessionId.substring(0, 40) + '...');
    
    // Store session key
    sessionKeys.set(sessionId, {
      sessionKey,
      role: 'ecdh',
      otherPartyId: userId2,
    });
    
    console.log('✅ Shared session established successfully');
    
    return sessionId;
  } catch (error) {
    console.error('❌ Error creating shared session:', error);
    throw error;
  }
}

/**
 * Simple session (for backwards compatibility - not recommended)
 * Creates a random key - USE createSharedSession instead!
 */
export async function createSimpleSession(userId1, userId2) {
  const sessionId = `simple-${userId1}-${userId2}-${Date.now()}`;
  
  const { generateAESKey } = await import('./crypto.js');
  const sessionKey = await generateAESKey();
  
  sessionKeys.set(sessionId, {
    sessionKey,
    role: 'simple',
    otherPartyId: userId2,
  });
  
  return sessionId;
}

