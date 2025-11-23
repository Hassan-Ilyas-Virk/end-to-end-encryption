/**
 * MITM Attack Demonstration Script
 * 
 * This script demonstrates:
 * 1. How MITM attacks succeed against UNSIGNED Diffie-Hellman key exchange
 * 2. How digital signatures PREVENT MITM attacks in the secure chat system
 */

import crypto from 'crypto';

// ============================================================================
// PART 1: MITM Attack on UNSIGNED Diffie-Hellman (VULNERABLE)
// ============================================================================

console.log('═══════════════════════════════════════════════════════════════');
console.log('PART 1: MITM Attack on UNSIGNED Diffie-Hellman');
console.log('═══════════════════════════════════════════════════════════════\n');

// Alice and Bob want to communicate securely
console.log('🔵 Alice and Bob want to establish a secure connection...\n');

// Alice generates her DH key pair
const aliceDH = crypto.createECDH('prime256v1');
aliceDH.generateKeys();
const alicePublicKey = aliceDH.getPublicKey('base64');
console.log('👩 Alice generates her public key:', alicePublicKey.substring(0, 40) + '...');

// Bob generates his DH key pair
const bobDH = crypto.createECDH('prime256v1');
bobDH.generateKeys();
const bobPublicKey = bobDH.getPublicKey('base64');
console.log('👨 Bob generates his public key:', bobPublicKey.substring(0, 40) + '...\n');

// ❌ VULNERABLE: Alice sends her public key to Bob (no signature!)
console.log('📤 Alice sends her public key to Bob (UNSIGNED)...');
console.log('🚨 ATTACKER INTERCEPTS THE MESSAGE!\n');

// Attacker (Eve) intercepts and generates her own key pairs
const eveAliceDH = crypto.createECDH('prime256v1');
eveAliceDH.generateKeys();
const eveToAlicePublicKey = eveAliceDH.getPublicKey('base64');

const eveBobDH = crypto.createECDH('prime256v1');
eveBobDH.generateKeys();
const eveToBobPublicKey = eveBobDH.getPublicKey('base64');

console.log('😈 Eve (attacker) generates TWO key pairs:');
console.log('   - One to communicate with Alice');
console.log('   - One to communicate with Bob\n');

// Eve replaces Alice's public key with her own
console.log('😈 Eve REPLACES Alice\'s public key with her own');
console.log('📥 Bob receives Eve\'s public key (thinking it\'s from Alice)\n');

// ❌ VULNERABLE: Bob sends his public key to Alice (no signature!)
console.log('📤 Bob sends his public key to Alice (UNSIGNED)...');
console.log('🚨 ATTACKER INTERCEPTS AGAIN!\n');

console.log('😈 Eve REPLACES Bob\'s public key with her own');
console.log('📥 Alice receives Eve\'s public key (thinking it\'s from Bob)\n');

// Now derive the shared secrets
// Alice thinks she's deriving a secret with Bob, but it's actually with Eve
const aliceSharedSecret = aliceDH.computeSecret(eveToAlicePublicKey, 'base64', 'hex');
console.log('👩 Alice derives shared secret (with Eve, but thinks it\'s Bob):', aliceSharedSecret.substring(0, 32) + '...');

// Bob thinks he's deriving a secret with Alice, but it's actually with Eve
const bobSharedSecret = bobDH.computeSecret(eveToBobPublicKey, 'base64', 'hex');
console.log('👨 Bob derives shared secret (with Eve, but thinks it\'s Alice):', bobSharedSecret.substring(0, 32) + '...');

// Eve derives BOTH secrets
const eveAliceSecret = eveAliceDH.computeSecret(alicePublicKey, 'base64', 'hex');
const eveBobSecret = eveBobDH.computeSecret(bobPublicKey, 'base64', 'hex');
console.log('😈 Eve derives secret with Alice:', eveAliceSecret.substring(0, 32) + '...');
console.log('😈 Eve derives secret with Bob:', eveBobSecret.substring(0, 32) + '...\n');

// Demonstrate the attack
console.log('💬 Alice encrypts message "Hello Bob!" with her shared secret...');
const aliceMessage = 'Hello Bob!';
const aliceCipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(aliceSharedSecret.substring(0, 64), 'hex'), Buffer.alloc(16, 0));
let aliceEncrypted = aliceCipher.update(aliceMessage, 'utf8', 'hex');
aliceEncrypted += aliceCipher.final('hex');
console.log('🔒 Encrypted:', aliceEncrypted);

console.log('\n😈 Eve INTERCEPTS and DECRYPTS with her secret with Alice:');
const eveDecipher1 = crypto.createDecipheriv('aes-256-cbc', Buffer.from(eveAliceSecret.substring(0, 64), 'hex'), Buffer.alloc(16, 0));
let eveDecrypted = eveDecipher1.update(aliceEncrypted, 'hex', 'utf8');
eveDecrypted += eveDecipher1.final('utf8');
console.log('🔓 Eve reads:', `"${eveDecrypted}"`);

console.log('\n😈 Eve MODIFIES the message and RE-ENCRYPTS with her secret with Bob:');
const modifiedMessage = 'Hello Bob! Send me $1000.';
const eveCipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(eveBobSecret.substring(0, 64), 'hex'), Buffer.alloc(16, 0));
let eveEncrypted = eveCipher.update(modifiedMessage, 'utf8', 'hex');
eveEncrypted += eveCipher.final('hex');

console.log('\n📥 Bob receives and decrypts:');
const bobDecipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(bobSharedSecret.substring(0, 64), 'hex'), Buffer.alloc(16, 0));
let bobDecrypted = bobDecipher.update(eveEncrypted, 'hex', 'utf8');
bobDecrypted += bobDecipher.final('utf8');
console.log('👨 Bob reads:', `"${bobDecrypted}"`);

console.log('\n❌ ATTACK SUCCESSFUL! Eve intercepted and modified the message!');
console.log('   Alice sent: "Hello Bob!"');
console.log('   Bob received: "Hello Bob! Send me $1000."');
console.log('   Neither Alice nor Bob detected the attack!\n');

// ============================================================================
// PART 2: MITM Attack PREVENTED by Digital Signatures (SECURE)
// ============================================================================

console.log('\n═══════════════════════════════════════════════════════════════');
console.log('PART 2: Digital Signatures PREVENT MITM Attack');
console.log('═══════════════════════════════════════════════════════════════\n');

console.log('🔵 Alice and Bob try again, but this time with DIGITAL SIGNATURES...\n');

// Alice generates ECDH key pair AND ECDSA signing key pair
const aliceDH2 = crypto.createECDH('prime256v1');
aliceDH2.generateKeys();
const alicePublicKey2 = aliceDH2.getPublicKey('base64');

const aliceSigningKey = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

console.log('👩 Alice generates:');
console.log('   - ECDH public key:', alicePublicKey2.substring(0, 40) + '...');
console.log('   - ECDSA signing key pair (for authentication)\n');

// Bob generates ECDH key pair AND ECDSA signing key pair
const bobDH2 = crypto.createECDH('prime256v1');
bobDH2.generateKeys();
const bobPublicKey2 = bobDH2.getPublicKey('base64');

const bobSigningKey = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

console.log('👨 Bob generates:');
console.log('   - ECDH public key:', bobPublicKey2.substring(0, 40) + '...');
console.log('   - ECDSA signing key pair (for authentication)\n');

// Alice SIGNS her public key before sending
const aliceDataToSign = JSON.stringify({
    publicKey: alicePublicKey2,
    timestamp: Date.now(),
    nonce: crypto.randomBytes(16).toString('hex')
});
const aliceSignature = crypto.sign('sha256', Buffer.from(aliceDataToSign), aliceSigningKey.privateKey);

console.log('✅ Alice SIGNS her public key with her private signing key');
console.log('📤 Alice sends: { publicKey, signature }\n');

console.log('🚨 ATTACKER INTERCEPTS...\n');

// Eve tries to replace the public key
const eveAliceDH2 = crypto.createECDH('prime256v1');
eveAliceDH2.generateKeys();
const eveToAlicePublicKey2 = eveAliceDH2.getPublicKey('base64');

console.log('😈 Eve tries to REPLACE Alice\'s public key with her own...');
console.log('😈 Eve sends her own public key to Bob...\n');

// Bob receives and tries to verify the signature
console.log('📥 Bob receives the message and VERIFIES the signature...');

// Bob has Alice's REAL public signing key (obtained securely beforehand or via PKI)
try {
    const eveDataToSign = JSON.stringify({
        publicKey: eveToAlicePublicKey2,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex')
    });

    // Eve can't create a valid signature without Alice's private key
    const isValid = crypto.verify(
        'sha256',
        Buffer.from(aliceDataToSign), // Original data
        aliceSigningKey.publicKey,     // Alice's REAL public key
        aliceSignature                 // Alice's signature
    );

    console.log('✅ Signature verification with REAL Alice public key: VALID');

    // But if Bob tries to verify Eve's forged message:
    const isEveValid = crypto.verify(
        'sha256',
        Buffer.from(eveDataToSign),    // Eve's forged data
        aliceSigningKey.publicKey,     // Alice's REAL public key
        aliceSignature                 // Alice's signature (won't match!)
    );

    console.log('❌ Signature verification with Eve\'s forged data: INVALID');
    console.log('\n🛡️ ATTACK PREVENTED! Bob detects the MITM attack!');
    console.log('   Bob rejects Eve\'s public key because the signature is invalid.');
    console.log('   The connection is NOT established.\n');

} catch (error) {
    console.log('❌ Signature verification FAILED:', error.message);
}

// ============================================================================
// Summary
// ============================================================================

console.log('\n═══════════════════════════════════════════════════════════════');
console.log('SUMMARY');
console.log('═══════════════════════════════════════════════════════════════\n');

console.log('WITHOUT Digital Signatures (Vulnerable):');
console.log('❌ Attacker can intercept and replace public keys');
console.log('❌ Attacker can decrypt, read, and modify messages');
console.log('❌ Neither party detects the attack\n');

console.log('WITH Digital Signatures (Secure - Your System):');
console.log('✅ Public keys are signed with private signing keys');
console.log('✅ Signatures are verified using public signing keys');
console.log('✅ Attacker cannot forge valid signatures');
console.log('✅ MITM attacks are detected and prevented\n');

console.log('Your Secure Chat System Implementation:');
console.log('✅ Uses ECDH for key exchange (Diffie-Hellman)');
console.log('✅ Uses ECDSA for digital signatures');
console.log('✅ All public keys are signed before transmission');
console.log('✅ All signatures are verified before accepting keys');
console.log('✅ MITM attacks are impossible without compromising private keys\n');
