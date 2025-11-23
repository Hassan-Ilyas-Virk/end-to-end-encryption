import { useState } from 'react';
import { logoutUser, updateUserKeys } from '../utils/auth-mongo';
import {
  generateECDHKeyPair,
  generateECDSAKeyPair,
  exportPublicKey,
  exportPrivateKey,
} from '../utils/crypto';
import { storeKey } from '../utils/keyStorage';
import api from '../config/api';

function KeySetup({ user, onComplete }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleGenerateKeys() {
    setLoading(true);
    setError('');

    try {
      console.log('🔑 Generating new encryption keys...');
      console.log('User ID for update:', user.id);


      // Generate new key pairs
      const ecdhKeyPair = await generateECDHKeyPair();
      const ecdsaKeyPair = await generateECDSAKeyPair();

      // Export keys
      const ecdhPublicKey = await exportPublicKey(ecdhKeyPair.publicKey);
      const ecdhPrivateKey = await exportPrivateKey(ecdhKeyPair.privateKey);
      const ecdsaPublicKey = await exportPublicKey(ecdsaKeyPair.publicKey);
      const ecdsaPrivateKey = await exportPrivateKey(ecdsaKeyPair.privateKey);

      console.log('✓ Keys generated');

      // Store private keys in IndexedDB
      await storeKey(user.id, 'ecdh-private', ecdhPrivateKey);
      await storeKey(user.id, 'ecdsa-private', ecdsaPrivateKey);

      console.log('✓ Private keys stored in IndexedDB');

      // Update public keys on server
      await updateUserKeys(user.id, ecdhPublicKey, ecdsaPublicKey);

      console.log('✓ Public keys updated in database');
      console.log('✓ Key setup complete!');

      // Reload the page to ensure all components load with new keys
      onComplete();
      window.location.reload();
    } catch (err) {
      console.error('Error generating keys:', err);
      setError(err.message || 'Failed to generate keys');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="key-setup-container">
      <div className="key-setup-card">
        <h2>Encryption Keys Required</h2>

        <div className="key-setup-message">
          <p>
            Your encryption keys are missing. This can happen if:
          </p>
          <ul>
            <li>You logged in from a new device or browser</li>
            <li>Your browser data was cleared</li>
            <li>You're using incognito/private mode</li>
          </ul>
        </div>

        <div className="warning-box">
          <h3>Important</h3>
          <p>
            Generating new keys means you won't be able to decrypt <strong>previously sent messages</strong>.
            This is a security feature - your old messages remain encrypted with your old keys.
          </p>
          <p style={{ marginTop: '10px' }}>
            <strong>What will work:</strong>
          </p>
          <ul style={{ marginTop: '5px', marginBottom: '0' }}>
            <li>You can send and receive <strong>new messages</strong> after generating keys</li>
            <li>Other users will be able to send you messages using your new public keys</li>
            <li>Your new keys will be stored securely in your browser and on the server</li>
          </ul>
          <p style={{ marginTop: '10px' }}>
            <strong>What won't work:</strong>
          </p>
          <ul style={{ marginTop: '5px', marginBottom: '0' }}>
            <li>Old messages sent before key regeneration cannot be decrypted</li>
            <li>You will see "Unable to decrypt" errors for old messages (this is expected)</li>
          </ul>
        </div>

        {error && <div className="error-message">{error}</div>}

        <button
          onClick={handleGenerateKeys}
          className="btn-primary"
          disabled={loading}
        >
          {loading ? 'Generating Keys...' : 'Generate New Encryption Keys'}
        </button>

        <div className="key-info">
          <h4>What happens when you generate keys:</h4>
          <ul>
            <li>New ECDH key pair for secure key exchange</li>
            <li>New ECDSA key pair for digital signatures</li>
            <li>Private keys stored securely in your browser</li>
            <li>Public keys shared with other users</li>
            <li>You can send and receive new encrypted messages</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default KeySetup;

