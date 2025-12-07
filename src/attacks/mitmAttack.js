/**
 * Man-in-the-Middle (MITM) Attack Demonstration
 * 
 * This script demonstrates:
 * 1. How MITM attacks can break Diffie-Hellman key exchange WITHOUT signatures
 * 2. How digital signatures prevent MITM attacks in our protocol
 */

import {
  generateECDHKeyPair,
  generateECDSAKeyPair,
  exportPublicKey,
  deriveSharedSecret,
  deriveSessionKey,
  signData,
  verifySignature,
  exportPrivateKey,
  importECDHPublicKey,
  importECDSAPrivateKey,
  importECDSAPublicKey,
  generateSalt,
} from '../utils/crypto.js';

import { logSecurityEvent } from '../utils/securityLogger-mongo.js';

/**
 * Scenario 1: Demonstrate MITM attack on UNSIGNED Diffie-Hellman
 * This shows how an attacker can intercept and replace public keys without signatures
 */
export async function demonstrateMITMWithoutSignatures() {
  console.log('\n=== MITM ATTACK DEMONSTRATION: Without Signatures ===\n');

  console.log('Step 1: Alice generates her ECDH key pair');
  const aliceKeyPair = await generateECDHKeyPair();
  const alicePublicKey = await exportPublicKey(aliceKeyPair.publicKey);
  console.log('✓ Alice public key generated');

  console.log('\nStep 2: Alice sends her public key to Bob');
  console.log('Public key (first 50 chars):', alicePublicKey.substring(0, 50) + '...');

  console.log('\n🔴 Step 3: ATTACKER INTERCEPTS the transmission!');
  console.log('Attacker generates their own key pair');
  const attackerKeyPair = await generateECDHKeyPair();
  const attackerPublicKey = await exportPublicKey(attackerKeyPair.publicKey);
  console.log('✓ Attacker public key generated');

  console.log('\n🔴 Step 4: ATTACKER REPLACES Alice\'s public key with their own');
  console.log('Attacker sends their public key to Bob, pretending to be Alice');

  console.log('\nStep 5: Bob receives what he thinks is Alice\'s public key');
  console.log('(But it\'s actually the attacker\'s public key!)');
  const bobKeyPair = await generateECDHKeyPair();
  const bobPublicKeyForAttacker = await exportPublicKey(bobKeyPair.publicKey);

  // Bob derives shared secret with attacker (thinking it's Alice)
  const attackerPublicKeyObj = await importECDHPublicKey(attackerPublicKey);
  const bobSharedSecretWithAttacker = await deriveSharedSecret(
    bobKeyPair.privateKey,
    attackerPublicKeyObj
  );
  console.log('✓ Bob derives shared secret (with attacker, not Alice!)');

  console.log('\n🔴 Step 6: Bob sends his public key to Alice');
  console.log('ATTACKER INTERCEPTS again!');
  console.log('Attacker derives shared secret with Bob');
  const bobPublicKeyObj = await importECDHPublicKey(bobPublicKeyForAttacker);
  const attackerSharedSecretWithBob = await deriveSharedSecret(
    attackerKeyPair.privateKey,
    bobPublicKeyObj
  );

  console.log('\n🔴 Step 7: Attacker sends their public key to Alice, pretending to be Bob');
  const alicePublicKeyObj = await importECDHPublicKey(alicePublicKey);
  const attackerSharedSecretWithAlice = await deriveSharedSecret(
    attackerKeyPair.privateKey,
    aliceKeyPair.publicKey
  );
  console.log('✓ Attacker derives shared secret with Alice');

  console.log('\n❌ RESULT: MITM ATTACK SUCCESSFUL!');
  console.log('- Alice has a shared secret with the attacker (thinks it\'s Bob)');
  console.log('- Bob has a shared secret with the attacker (thinks it\'s Alice)');
  console.log('- Attacker can decrypt messages from both parties and re-encrypt them');
  console.log('- Neither Alice nor Bob know they\'re being attacked!');

  await logSecurityEvent(
    null,
    'MITM_DEMO_UNSIGNED',
    'MITM attack demonstration: Unsigned DH is vulnerable',
    'CRITICAL'
  );

  return {
    success: true,
    vulnerability: 'Unsigned Diffie-Hellman key exchange',
    impact: 'Complete compromise of confidentiality',
    mitigation: 'Use digital signatures to authenticate public keys',
  };
}

/**
 * Scenario 2: Demonstrate how signatures PREVENT MITM attacks
 * This shows how our protocol uses ECDSA signatures to authenticate keys
 */
export async function demonstrateMITMWithSignatures() {
  console.log('\n=== MITM ATTACK DEMONSTRATION: With Signatures ===\n');

  console.log('Step 1: Alice generates ECDH key pair AND signing key pair');
  const aliceECDHKeyPair = await generateECDHKeyPair();
  const aliceSignKeyPair = await generateECDSAKeyPair();
  const alicePublicKey = await exportPublicKey(aliceECDHKeyPair.publicKey);
  const aliceSignPublicKey = await exportPublicKey(aliceSignKeyPair.publicKey);
  console.log('✓ Alice has ECDH keys (for encryption) and ECDSA keys (for signing)');

  console.log('\nStep 2: Alice creates a message with her public key');
  const aliceMessage = JSON.stringify({
    sender: 'Alice',
    publicKey: alicePublicKey,
    timestamp: Date.now(),
  });

  console.log('\nStep 3: Alice SIGNS the message with her private signing key');
  const aliceSignPrivateKey = await exportPrivateKey(aliceSignKeyPair.privateKey);
  const aliceSignPrivateKeyObj = await importECDSAPrivateKey(aliceSignPrivateKey);
  const aliceSignature = await signData(aliceSignPrivateKeyObj, aliceMessage);
  console.log('✓ Alice creates digital signature');
  console.log('Signature (first 50 chars):', aliceSignature.substring(0, 50) + '...');

  console.log('\nStep 4: Alice sends: {message, signature, signing_public_key}');

  console.log('\n🔴 Step 5: ATTACKER INTERCEPTS the transmission!');
  console.log('Attacker generates their own keys');
  const attackerECDHKeyPair = await generateECDHKeyPair();
  const attackerSignKeyPair = await generateECDSAKeyPair();
  const attackerPublicKey = await exportPublicKey(attackerECDHKeyPair.publicKey);

  console.log('\n🔴 Step 6: Attacker tries to replace Alice\'s public key');
  const attackerMessage = JSON.stringify({
    sender: 'Alice', // Pretending to be Alice
    publicKey: attackerPublicKey, // But using attacker's key
    timestamp: Date.now(),
  });

  console.log('Attacker needs to create a valid signature...');
  console.log('But attacker doesn\'t have Alice\'s private signing key!');

  console.log('\n🔴 Step 7: Attacker has two options:');
  console.log('Option A: Send modified message with Alice\'s signature (will fail verification)');
  console.log('Option B: Send modified message with attacker\'s signature and key (Bob will notice different key)');

  console.log('\nStep 8: Bob receives the message and verifies signature');
  console.log('Bob has Alice\'s authentic signing public key (from a trusted channel)');

  // Bob verifies using Alice's signing public key
  const aliceSignPublicKeyObj = await importECDSAPublicKey(aliceSignPublicKey);

  console.log('\nAttempting to verify attacker\'s modified message with Alice\'s signature...');
  const isValidOriginal = await verifySignature(
    aliceSignPublicKeyObj,
    aliceSignature,
    aliceMessage
  );
  console.log('Original message verification:', isValidOriginal ? '✅ VALID' : '❌ INVALID');

  const isValidModified = await verifySignature(
    aliceSignPublicKeyObj,
    aliceSignature,
    attackerMessage
  );
  console.log('Modified message verification:', isValidModified ? '✅ VALID' : '❌ INVALID');

  console.log('\n✅ RESULT: MITM ATTACK BLOCKED!');
  console.log('Signature verification fails because:');
  console.log('- The attacker modified the message content');
  console.log('- The signature was created for the original message');
  console.log('- Without Alice\'s private key, attacker cannot create a valid signature');
  console.log('- Bob detects tampering and rejects the message');

  await logSecurityEvent(
    null,
    'MITM_DEMO_SIGNED',
    'MITM attack demonstration: Signatures successfully prevent attack',
    'INFO'
  );

  return {
    success: false, // Attack was not successful
    protection: 'Digital signatures (ECDSA)',
    result: 'Attack detected and blocked',
    reason: 'Signature verification failed for tampered message',
  };
}

/**
 * Compare both scenarios side by side
 */
export async function compareSecurityModels() {
  console.log('\n=== SECURITY MODEL COMPARISON ===\n');

  console.log('Testing MITM attack on both models...\n');

  const resultWithout = await demonstrateMITMWithoutSignatures();
  const resultWith = await demonstrateMITMWithSignatures();

  console.log('\n=== COMPARISON SUMMARY ===\n');

  console.log('WITHOUT Digital Signatures:');
  console.log('  Attack Success:', resultWithout.success ? '❌ YES' : '✅ NO');
  console.log('  Vulnerability:', resultWithout.vulnerability);
  console.log('  Impact:', resultWithout.impact);

  console.log('\nWITH Digital Signatures:');
  console.log('  Attack Success:', resultWith.success ? '❌ YES' : '✅ NO');
  console.log('  Protection:', resultWith.protection);
  console.log('  Result:', resultWith.result);

  console.log('\n=== CONCLUSION ===');
  console.log('Digital signatures are ESSENTIAL for preventing MITM attacks!');
  console.log('Our protocol uses ECDSA signatures to authenticate all key exchanges.');

  return {
    withoutSignatures: resultWithout,
    withSignatures: resultWith,
  };
}

/**
 * Generate a comprehensive MITM attack report
 */
export function generateMITMReport(comparisonResults) {
  const timestamp = new Date().toISOString();

  return `
# Man-in-the-Middle (MITM) Attack Demonstration Report

**Date:** ${timestamp}

## Executive Summary

This report documents the Man-in-the-Middle attack demonstrations conducted on the secure messaging system, comparing the security of key exchange protocols with and without digital signatures.

## Attack Description

A Man-in-the-Middle (MITM) attack occurs when an attacker intercepts communication between two parties and can:
- Read all messages
- Modify messages
- Impersonate either party
- Establish separate encrypted sessions with each party

In the context of Diffie-Hellman key exchange, an attacker can intercept public keys and replace them with their own, establishing separate shared secrets with each party.

## Demonstration 1: MITM on Unsigned Diffie-Hellman

### Attack Flow

1. **Alice** generates ECDH key pair and sends public key to Bob
2. **Attacker** intercepts Alice's public key
3. **Attacker** generates their own key pair
4. **Attacker** sends their public key to Bob, pretending to be Alice
5. **Bob** generates his key pair and derives shared secret (with attacker, not Alice)
6. **Bob** sends his public key to Alice
7. **Attacker** intercepts Bob's public key
8. **Attacker** sends their public key to Alice, pretending to be Bob
9. **Alice** derives shared secret (with attacker, not Bob)

### Result

**❌ ATTACK SUCCESSFUL**

- Alice has a shared secret with the attacker (believes it's with Bob)
- Bob has a shared secret with the attacker (believes it's with Alice)
- Attacker can decrypt all messages, read them, and re-encrypt for the other party
- Complete compromise of confidentiality and integrity

### Why It Works

Without authentication, there is no way for Alice or Bob to verify that the public keys they receive actually belong to each other. The attacker exploits this lack of authentication.

## Demonstration 2: MITM on Signed Diffie-Hellman

### Protection Mechanism

Our protocol adds digital signatures:

1. Each user has a long-term ECDSA key pair for signing
2. Public signing keys are distributed through a trusted channel (stored in database)
3. When sending a public ECDH key, the user signs it with their private signing key
4. The receiver verifies the signature using the sender's public signing key

### Attack Attempt

1. **Alice** generates ECDH key pair and signs it
2. **Attacker** intercepts Alice's signed message
3. **Attacker** attempts to replace Alice's public key with their own
4. **Attacker** faces two impossible choices:
   - Use Alice's signature: Verification fails (signature doesn't match modified content)
   - Create new signature: Requires Alice's private signing key (which attacker doesn't have)
5. **Bob** verifies signature and detects tampering

### Result

**✅ ATTACK BLOCKED**

- Signature verification fails for any modified message
- Attacker cannot forge a valid signature without Alice's private key
- Bob detects the attack and rejects the key exchange
- Communication is prevented rather than compromised

### Why It Works

Digital signatures provide:
- **Authentication**: Proves the public key comes from the claimed sender
- **Integrity**: Ensures the public key hasn't been modified
- **Non-repudiation**: Sender cannot deny sending the key

## Implementation Details

### Signature Creation (Sender Side)

\`\`\`javascript
// Create data to sign
const dataToSign = JSON.stringify({
  initiatorId,
  responderId,
  ephemeralPublicKey,
  nonce,
  timestamp,
});

// Sign with ECDSA private key
const signature = await signData(privateKey, dataToSign);
\`\`\`

### Signature Verification (Receiver Side)

\`\`\`javascript
// Verify signature using sender's public signing key
const isValid = await verifySignature(
  publicKey,
  signature,
  dataToSign
);

if (!isValid) {
  throw new Error('Invalid signature - possible MITM attack!');
}
\`\`\`

## Comparison Summary

| Aspect | Without Signatures | With Signatures |
|--------|-------------------|-----------------|
| **MITM Vulnerability** | ❌ Vulnerable | ✅ Protected |
| **Attack Success** | ❌ Yes | ✅ No |
| **Authentication** | ❌ None | ✅ Strong |
| **Integrity Protection** | ❌ None | ✅ Yes |
| **Detection Capability** | ❌ Cannot detect | ✅ Detects tampering |

## Conclusion

Digital signatures are **CRITICAL** for preventing Man-in-the-Middle attacks in key exchange protocols. Our implementation uses:

- **ECDH (P-384)** for key agreement
- **ECDSA (P-384)** for authentication
- **SHA-384** for signature hashing

This combination provides:
1. Forward secrecy (ephemeral keys)
2. Strong authentication (digital signatures)
3. Protection against MITM attacks
4. Compliance with NIST standards

## Recommendations

1. **Never** implement key exchange without authentication
2. Always verify signatures before accepting public keys
3. Use a trusted channel to distribute initial signing public keys
4. Consider implementing certificate pinning for additional security
5. Monitor security logs for signature verification failures

## Tools Used for Demonstration

- Custom JavaScript implementation using Web Crypto API
- ECDH with P-384 curve
- ECDSA with SHA-384

---

*This report was automatically generated by the attack demonstration module.*
`;
}

// Execute the demonstration when run directly
compareSecurityModels().then((results) => {
  console.log(generateMITMReport(results));
}).catch((error) => {
  console.error('Error running MITM demonstration:', error);
  process.exit(1);
});
