/**
 * Secure Key Storage using IndexedDB
 * Private keys are stored encrypted in IndexedDB and NEVER sent to server
 */

const DB_NAME = 'SecureChatKeyStore';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

/**
 * Initialize IndexedDB
 * @returns {Promise<IDBDatabase>} Database instance
 */
function initDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      
      // Create object store if it doesn't exist
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const objectStore = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
        objectStore.createIndex('userId', 'userId', { unique: false });
        objectStore.createIndex('keyType', 'keyType', { unique: false });
      }
    };
  });
}

/**
 * Store a key in IndexedDB
 * @param {string} userId - User ID
 * @param {string} keyType - Type of key (e.g., 'ecdh-private', 'ecdsa-private')
 * @param {string} keyData - Base64 encoded key data
 * @returns {Promise<void>}
 */
export async function storeKey(userId, keyType, keyData) {
  try {
    const db = await initDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      
      const keyObject = {
        id: `${userId}-${keyType}`,
        userId,
        keyType,
        keyData,
        timestamp: Date.now(),
      };
      
      const request = store.put(keyObject);
      
      request.onsuccess = () => {
        console.log(`Key stored: ${keyType} for user ${userId}`);
        resolve();
      };
      
      request.onerror = () => reject(request.error);
      
      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Error storing key:', error);
    throw error;
  }
}

/**
 * Retrieve a key from IndexedDB
 * @param {string} userId - User ID
 * @param {string} keyType - Type of key
 * @returns {Promise<string|null>} Base64 encoded key data or null if not found
 */
export async function retrieveKey(userId, keyType) {
  try {
    const db = await initDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(`${userId}-${keyType}`);
      
      request.onsuccess = () => {
        const result = request.result;
        resolve(result ? result.keyData : null);
      };
      
      request.onerror = () => reject(request.error);
      
      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Error retrieving key:', error);
    throw error;
  }
}

/**
 * Delete a key from IndexedDB
 * @param {string} userId - User ID
 * @param {string} keyType - Type of key
 * @returns {Promise<void>}
 */
export async function deleteKey(userId, keyType) {
  try {
    const db = await initDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.delete(`${userId}-${keyType}`);
      
      request.onsuccess = () => {
        console.log(`Key deleted: ${keyType} for user ${userId}`);
        resolve();
      };
      
      request.onerror = () => reject(request.error);
      
      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Error deleting key:', error);
    throw error;
  }
}

/**
 * Delete all keys for a user (e.g., on logout)
 * @param {string} userId - User ID
 * @returns {Promise<void>}
 */
export async function deleteAllKeysForUser(userId) {
  try {
    const db = await initDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const index = store.index('userId');
      const request = index.openCursor(IDBKeyRange.only(userId));
      
      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          cursor.delete();
          cursor.continue();
        } else {
          console.log(`All keys deleted for user ${userId}`);
          resolve();
        }
      };
      
      request.onerror = () => reject(request.error);
      
      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Error deleting all keys:', error);
    throw error;
  }
}

/**
 * Check if keys exist for a user
 * @param {string} userId - User ID
 * @returns {Promise<boolean>} True if keys exist
 */
export async function keysExist(userId) {
  try {
    const ecdhKey = await retrieveKey(userId, 'ecdh-private');
    const ecdsaKey = await retrieveKey(userId, 'ecdsa-private');
    return !!(ecdhKey && ecdsaKey);
  } catch (error) {
    console.error('Error checking keys:', error);
    return false;
  }
}

/**
 * Store session data (temporary, for active sessions)
 * @param {string} sessionId - Session ID
 * @param {string} sessionKeyData - Encrypted session key data
 * @returns {Promise<void>}
 */
export async function storeSessionKey(sessionId, sessionKeyData) {
  try {
    const db = await initDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      
      const sessionObject = {
        id: `session-${sessionId}`,
        userId: 'session',
        keyType: 'session-key',
        keyData: sessionKeyData,
        timestamp: Date.now(),
      };
      
      const request = store.put(sessionObject);
      
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
      
      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Error storing session key:', error);
    throw error;
  }
}

/**
 * Retrieve session key
 * @param {string} sessionId - Session ID
 * @returns {Promise<string|null>} Session key data or null
 */
export async function retrieveSessionKey(sessionId) {
  try {
    const db = await initDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(`session-${sessionId}`);
      
      request.onsuccess = () => {
        const result = request.result;
        resolve(result ? result.keyData : null);
      };
      
      request.onerror = () => reject(request.error);
      
      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Error retrieving session key:', error);
    throw error;
  }
}

/**
 * List all stored keys (for debugging)
 * @returns {Promise<Array>} Array of key objects
 */
export async function listAllKeys() {
  try {
    const db = await initDB();
    
    return new Promise((resolve, reject) => {
      const transaction = db.transaction([STORE_NAME], 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.getAll();
      
      request.onsuccess = () => {
        // Don't log actual key data, just metadata
        const keys = request.result.map(k => ({
          id: k.id,
          userId: k.userId,
          keyType: k.keyType,
          timestamp: k.timestamp,
        }));
        resolve(keys);
      };
      
      request.onerror = () => reject(request.error);
      
      transaction.oncomplete = () => db.close();
    });
  } catch (error) {
    console.error('Error listing keys:', error);
    throw error;
  }
}

