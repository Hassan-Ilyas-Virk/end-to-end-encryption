/**
 * End-to-End Encrypted Messaging with MongoDB
 */

import api from '../config/api.js';
import {
  encryptAES,
  decryptAES,
  generateIV,
  generateNonce,
  signData,
  verifySignature,
  importECDSAPrivateKey,
  importECDSAPublicKey,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from './crypto.js';

import {
  logMessageCrypto,
  logReplayAttack,
  logInvalidSignature,
} from './securityLogger-mongo.js';

/**
 * Encrypt and send a message
 */
export async function encryptAndSendMessage(
  senderId,
  receiverId,
  message,
  sessionKey,
  senderSignPrivateKey
) {
  try {
    console.log('🔒 Encrypting message...');
    
    // Generate fresh IV
    const iv = generateIV();
    const ivBase64 = arrayBufferToBase64(iv);
    
    // Generate nonce and timestamp
    const nonce = generateNonce();
    const timestamp = Date.now();
    
    // Generate sequence number (simplified - could be improved)
    const sequenceNumber = Math.floor(Math.random() * 1000000);
    
    // Encrypt message
    const { ciphertext, authTag } = await encryptAES(sessionKey, message, iv);
    
    console.log('✓ Message encrypted with AES-256-GCM');
    
    // Create metadata for signature (excluding senderId/receiverId as backend sets them)
    const metadata = JSON.stringify({
      nonce,
      timestamp,
      sequenceNumber,
      ivBase64,
    });
    
    // Sign metadata + ciphertext
    const privateKey = await importECDSAPrivateKey(senderSignPrivateKey);
    const dataToSign = `${metadata}:${ciphertext}`;
    const signature = await signData(privateKey, dataToSign);
    
    console.log('✓ Message signed');
    
    // Send to backend
    const response = await api.post('/messages', {
      receiverId,
      encryptedContent: ciphertext,
      iv: ivBase64,
      authTag,
      nonce,
      timestamp,
      sequenceNumber,
      signature,
    });
    
    await logMessageCrypto(senderId, 'encrypt', true, response.data._id);
    
    console.log('✓ Message sent successfully');
    
    return response.data;
  } catch (error) {
    console.error('Error encrypting and sending message:', error);
    await logMessageCrypto(senderId, 'encrypt', false, 'unknown');
    throw error;
  }
}

/**
 * Decrypt message for display
 */
export async function decryptMessageForDisplay(
  messageData,
  sessionKey,
  senderSignPublicKey
) {
  try {
    const {
      sender_id: senderId,
      receiver_id: receiverId,
      encrypted_content: ciphertext,
      iv: ivBase64,
      auth_tag: authTag,
      nonce,
      timestamp,
      sequence_number: sequenceNumber,
      signature,
    } = messageData;
    
    console.log('🔓 Decrypting message from:', senderId.substring(0, 8));
    
    // Verify signature - try new format first (without user IDs)
    const metadataNew = JSON.stringify({
      nonce,
      timestamp,
      sequenceNumber,
      ivBase64,
    });
    
    const dataToVerifyNew = `${metadataNew}:${ciphertext}`;
    
    console.log('Verifying signature (new format)...');
    const publicKey = await importECDSAPublicKey(senderSignPublicKey);
    let isValid = await verifySignature(publicKey, signature, dataToVerifyNew);
    
    // If new format fails, try old format (backwards compatibility)
    if (!isValid) {
      console.log('New format failed, trying old format...');
      const metadataOld = JSON.stringify({
        senderId,
        receiverId,
        nonce,
        timestamp,
        sequenceNumber,
        ivBase64,
      });
      const dataToVerifyOld = `${metadataOld}:${ciphertext}`;
      isValid = await verifySignature(publicKey, signature, dataToVerifyOld);
    }
    
    if (!isValid) {
      console.error('❌ Signature verification failed with both formats!');
      throw new Error('Invalid signature on message');
    }
    
    console.log('✓ Signature verified');
    
    // Convert IV from base64
    const iv = base64ToArrayBuffer(ivBase64);
    
    // Decrypt message
    const plaintext = await decryptAES(sessionKey, ciphertext, authTag, iv);
    
    console.log('✓ Message decrypted:', plaintext.substring(0, 30) + '...');
    
    return plaintext;
  } catch (error) {
    console.error('Error decrypting message:', error);
    throw error;
  }
}

/**
 * Get messages between two users
 */
export async function getMessages(userId1, userId2) {
  try {
    const response = await api.get(`/messages/${userId2}`);
    return response.data.map(msg => ({
      id: msg._id,
      sender_id: msg.senderId,
      receiver_id: msg.receiverId,
      encrypted_content: msg.encryptedContent,
      iv: msg.iv,
      auth_tag: msg.authTag,
      nonce: msg.nonce,
      timestamp: msg.timestamp,
      sequence_number: msg.sequenceNumber,
      signature: msg.signature,
      created_at: msg.createdAt,
    }));
  } catch (error) {
    console.error('Error getting messages:', error);
    throw error;
  }
}

/**
 * Delete a message
 */
export async function deleteMessage(messageId, userId) {
  try {
    await api.delete(`/messages/${messageId}`);
    console.log('✓ Message deleted');
  } catch (error) {
    console.error('Error deleting message:', error);
    throw error;
  }
}

