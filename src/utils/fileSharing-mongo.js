/**
 * End-to-End Encrypted File Sharing with MongoDB
 */

import api from '../config/api.js';
import {
  encryptAES,
  decryptAES,
  generateIV,
  generateNonce,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from './crypto.js';

import { logFileCrypto } from './securityLogger-mongo.js';

/**
 * Read file as ArrayBuffer
 */
function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => resolve(e.target.result);
    reader.onerror = (e) => reject(e);
    reader.readAsArrayBuffer(file);
  });
}

/**
 * Encrypt and upload a file
 */
export async function encryptAndUploadFile(file, senderId, receiverId, sessionKey) {
  try {
    console.log(`🔒 Encrypting file: ${file.name} (${file.size} bytes)`);
    
    // Read file data
    const fileData = await readFileAsArrayBuffer(file);
    const fileString = arrayBufferToBase64(fileData);
    
    // Generate IV and nonce
    const iv = generateIV();
    const ivBase64 = arrayBufferToBase64(iv);
    const nonce = generateNonce();
    const timestamp = Date.now();
    
    // Encrypt file data
    const { ciphertext, authTag } = await encryptAES(sessionKey, fileString, iv);
    
    console.log('✓ File encrypted');
    
    // Upload to backend
    const response = await api.post('/files', {
      receiverId,
      filename: file.name,
      encryptedData: ciphertext,
      iv: ivBase64,
      authTag,
      nonce,
      timestamp,
      fileSize: file.size,
    });
    
    await logFileCrypto(senderId, 'encrypt', true, response.data._id, file.size);
    
    console.log('✓ Encrypted file uploaded');
    
    return response.data;
  } catch (error) {
    console.error('Error encrypting and uploading file:', error);
    await logFileCrypto(senderId, 'encrypt', false, 'unknown', file.size);
    throw error;
  }
}

/**
 * Download and decrypt a file
 */
export async function downloadAndDecryptFile(fileId, sessionKey, userId) {
  try {
    console.log('🔓 Downloading and decrypting file...');
    
    // Fetch encrypted file from backend
    const response = await api.get(`/files/download/${fileId}`);
    const fileData = response.data;
    
    const {
      filename,
      encryptedData: ciphertext,
      iv: ivBase64,
      authTag,
      fileSize,
    } = fileData;
    
    // Convert IV from base64
    const iv = base64ToArrayBuffer(ivBase64);
    
    // Decrypt file data
    const decryptedBase64 = await decryptAES(sessionKey, ciphertext, authTag, iv);
    const decryptedData = base64ToArrayBuffer(decryptedBase64);
    
    console.log('✓ File decrypted');
    
    await logFileCrypto(userId, 'decrypt', true, fileId, fileSize);
    
    return {
      filename,
      data: decryptedData,
      size: fileSize,
    };
  } catch (error) {
    console.error('Error downloading and decrypting file:', error);
    await logFileCrypto(userId, 'decrypt', false, fileId, 0);
    throw error;
  }
}

/**
 * Trigger browser download of decrypted file
 */
export function triggerFileDownload(data, filename) {
  const blob = new Blob([data]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  console.log(`✓ File download triggered: ${filename}`);
}

/**
 * Get files shared between two users
 */
export async function getSharedFiles(userId1, userId2) {
  try {
    const response = await api.get(`/files/${userId2}`);
    return response.data.map(file => ({
      id: file._id,
      filename: file.filename,
      file_size: file.fileSize,
      timestamp: file.timestamp,
      sender_id: file.senderId,
      receiver_id: file.receiverId,
      created_at: file.createdAt,
    }));
  } catch (error) {
    console.error('Error getting shared files:', error);
    throw error;
  }
}

/**
 * Delete an encrypted file
 */
export async function deleteEncryptedFile(fileId, userId) {
  try {
    await api.delete(`/files/${fileId}`);
    console.log('✓ File deleted');
  } catch (error) {
    console.error('Error deleting file:', error);
    throw error;
  }
}

