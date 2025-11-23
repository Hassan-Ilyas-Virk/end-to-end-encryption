/**
 * Authentication with MongoDB Backend
 * Replaces Supabase Auth
 */

import api from '../config/api.js';
import {
  generateECDHKeyPair,
  generateECDSAKeyPair,
  exportPublicKey,
  exportPrivateKey,
} from './crypto.js';
import {
  storeKey,
  retrieveKey,
  deleteAllKeysForUser,
  keysExist,
} from './keyStorage.js';
import { logSecurityEvent } from './securityLogger-mongo.js';

/**
 * Register a new user
 */
export async function registerUser(email, password, username) {
  try {
    console.log('📝 Registering new user...');

    // Generate cryptographic keys
    console.log('🔑 Generating cryptographic keys...');

    const ecdhKeyPair = await generateECDHKeyPair();
    const ecdsaKeyPair = await generateECDSAKeyPair();

    // Export keys
    const ecdhPublicKey = await exportPublicKey(ecdhKeyPair.publicKey);
    const ecdhPrivateKey = await exportPrivateKey(ecdhKeyPair.privateKey);
    const ecdsaPublicKey = await exportPublicKey(ecdsaKeyPair.publicKey);
    const ecdsaPrivateKey = await exportPrivateKey(ecdsaKeyPair.privateKey);

    console.log('✓ Keys generated');

    // Register with backend
    const response = await api.post('/auth/register', {
      email,
      password,
      username,
      publicKeyECDH: ecdhPublicKey,
      publicKeySign: ecdsaPublicKey,
    });

    const { user, token } = response.data;

    // Store auth token
    localStorage.setItem('authToken', token);

    // Store private keys in IndexedDB
    await storeKey(user.id, 'ecdh-private', ecdhPrivateKey);
    await storeKey(user.id, 'ecdsa-private', ecdsaPrivateKey);

    console.log('✓ Private keys stored in IndexedDB');
    console.log('✓ User registration complete');

    return { user, token };
  } catch (error) {
    console.error('Error registering user:', error);
    throw new Error(error.response?.data?.error || error.message);
  }
}

/**
 * Login user
 */
export async function loginUser(email, password) {
  try {
    console.log('🔐 Logging in...');

    const response = await api.post('/auth/login', {
      email,
      password,
    });

    const { user, token } = response.data;

    // Store auth token
    localStorage.setItem('authToken', token);

    // Check if keys exist in IndexedDB
    const hasKeys = await keysExist(user.id);

    if (!hasKeys) {
      console.warn('⚠️  Keys not found in IndexedDB');
    }

    console.log('✓ Login successful');

    return { user, hasKeys };
  } catch (error) {
    console.error('Error logging in:', error);
    throw new Error(error.response?.data?.error || error.message);
  }
}

/**
 * Logout user
 */
export async function logoutUser() {
  try {
    localStorage.removeItem('authToken');
    console.log('✓ Logged out successfully');
  } catch (error) {
    console.error('Error logging out:', error);
    throw error;
  }
}

/**
 * Get current user
 */
export async function getCurrentUser() {
  try {
    const token = localStorage.getItem('authToken');
    if (!token) {
      return null;
    }

    const response = await api.get('/auth/me');
    return response.data.user;
  } catch (error) {
    console.error('Error getting current user:', error);
    return null;
  }
}

/**
 * Get user's private keys from IndexedDB
 */
export async function getUserPrivateKeys(userId) {
  try {
    const ecdhPrivateKey = await retrieveKey(userId, 'ecdh-private');
    const ecdsaPrivateKey = await retrieveKey(userId, 'ecdsa-private');

    if (!ecdhPrivateKey || !ecdsaPrivateKey) {
      throw new Error('Private keys not found in IndexedDB');
    }

    return {
      ecdhPrivateKey,
      ecdsaPrivateKey,
    };
  } catch (error) {
    console.error('Error retrieving private keys:', error);
    throw error;
  }
}

/**
 * Get another user's public keys
 */
export async function getUserPublicKeys(userId) {
  try {
    const response = await api.get(`/users/${userId}/keys`);
    return {
      ecdhPublicKey: response.data.publicKeyECDH,
      ecdsaPublicKey: response.data.publicKeySign,
    };
  } catch (error) {
    console.error('Error getting public keys:', error);
    throw error;
  }
}

/**
 * Update user's public keys
 */
export async function updateUserKeys(userId, ecdhPublicKey, ecdsaPublicKey) {
  try {
    const response = await api.put(`/users/${userId}/keys`, {
      publicKeyECDH: ecdhPublicKey,
      publicKeySign: ecdsaPublicKey,
    });

    console.log('✓ Public keys updated on server');
    return response.data;
  } catch (error) {
    console.error('Error updating public keys:', error);
    throw error;
  }
}

/**
 * Get all users (for contact list)
 */
export async function getAllUsers() {
  try {
    const response = await api.get('/users');
    return response.data.map(user => ({
      id: user._id,
      username: user.username,
      created_at: user.createdAt,
    }));
  } catch (error) {
    console.error('Error fetching users:', error);
    return [];
  }
}

/**
 * Search for users by username
 */
export async function searchUsers(searchTerm) {
  try {
    const users = await getAllUsers();
    return users.filter(user =>
      user.username.toLowerCase().includes(searchTerm.toLowerCase())
    );
  } catch (error) {
    console.error('Error searching users:', error);
    return [];
  }
}

/**
 * Delete user account
 */
export async function deleteUserAccount(userId) {
  try {
    await deleteAllKeysForUser(userId);
    console.log('✓ User account deleted');
  } catch (error) {
    console.error('Error deleting user account:', error);
    throw error;
  }
}

/**
 * Change user password (not implemented in backend yet)
 */
export async function changePassword(newPassword) {
  throw new Error('Password change not yet implemented');
}

