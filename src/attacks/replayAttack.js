/**
 * Replay Attack Demonstration
 * 
 * This script demonstrates how replay attacks work and how our system prevents them
 * using simulated message data
 */

import {
  generateAESKey,
  encryptAES,
  decryptAES,
  generateIV,
  generateNonce,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from '../utils/crypto.js';

// Simulated nonce tracking (in real app, this would be in database/memory)
const usedNonces = new Set();
const processedMessages = new Map(); // messageId -> timestamp

/**
 * Simulate receiving and validating a message (with replay protection)
 */
async function validateMessage(messageData, sessionKey) {
  const { nonce, timestamp, sequenceNumber, ciphertext, iv, authTag, messageId } = messageData;

  // Check 1: Nonce uniqueness (prevents exact replay)
  if (usedNonces.has(nonce)) {
    throw new Error('REPLAY ATTACK DETECTED: Duplicate nonce! This message has already been processed.');
  }

  // Check 2: Timestamp freshness (prevents old message replay)
  const now = Date.now();
  const messageAge = now - timestamp;
  const maxAge = 10 * 60 * 1000; // 10 minutes

  if (messageAge > maxAge) {
    throw new Error(`REPLAY ATTACK DETECTED: Message too old! Age: ${Math.floor(messageAge / 1000)}s, Max: ${maxAge / 1000}s`);
  }

  if (timestamp > now + 60000) { // 1 minute tolerance for clock skew
    throw new Error('REPLAY ATTACK DETECTED: Message timestamp is in the future!');
  }

  // Check 3: Sequence number (prevents out-of-order replay)
  const lastSeq = processedMessages.get(messageId) || 0;
  if (sequenceNumber <= lastSeq) {
    throw new Error(`REPLAY ATTACK DETECTED: Invalid sequence number! Got ${sequenceNumber}, expected > ${lastSeq}`);
  }

  // All checks passed - decrypt message
  const ivBuffer = base64ToArrayBuffer(iv);
  const plaintext = await decryptAES(sessionKey, ciphertext, authTag, ivBuffer);

  // Mark as processed
  usedNonces.add(nonce);
  processedMessages.set(messageId, sequenceNumber);

  return plaintext;
}

/**
 * Demonstrate a successful message transmission
 */
async function demonstrateNormalMessage() {
  console.log('\n=== STEP 1: NORMAL MESSAGE TRANSMISSION ===\n');

  // Generate session key
  const sessionKey = await generateAESKey();
  console.log('✓ Session key established between Alice and Bob');

  // Alice sends a message
  const message = "Hello Bob! This is a secure message.";
  const iv = generateIV();
  const nonce = generateNonce();
  const timestamp = Date.now();
  const sequenceNumber = 1;
  const messageId = 'alice-bob-session';

  console.log('\nAlice sends message:');
  console.log('  Message:', message);
  console.log('  Nonce:', nonce.substring(0, 20) + '...');
  console.log('  Timestamp:', new Date(timestamp).toISOString());
  console.log('  Sequence:', sequenceNumber);

  // Encrypt
  const { ciphertext, authTag } = await encryptAES(sessionKey, message, iv);
  console.log('\n✓ Message encrypted with AES-256-GCM');

  const messageData = {
    messageId,
    nonce,
    timestamp,
    sequenceNumber,
    ciphertext,
    authTag,
    iv: arrayBufferToBase64(iv),
  };

  // Bob receives and validates
  console.log('\nBob receives and validates message...');
  const decrypted = await validateMessage(messageData, sessionKey);
  console.log('✓ All security checks passed');
  console.log('✓ Message decrypted:', decrypted);

  return { messageData, sessionKey };
}

/**
 * Demonstrate replay attack - exact replay
 */
async function demonstrateExactReplay(messageData, sessionKey) {
  console.log('\n\n=== STEP 2: REPLAY ATTACK - EXACT REPLAY ===\n');

  console.log('🔴 ATTACKER intercepts the encrypted message');
  console.log('Attacker captures:');
  console.log('  - Encrypted content');
  console.log('  - Nonce:', messageData.nonce.substring(0, 20) + '...');
  console.log('  - Timestamp:', new Date(messageData.timestamp).toISOString());
  console.log('  - All metadata');

  console.log('\n🔴 ATTACKER attempts to replay the EXACT same message...\n');

  await new Promise(resolve => setTimeout(resolve, 500));

  try {
    await validateMessage(messageData, sessionKey);
    console.log('❌ SECURITY FAILURE: Replay attack succeeded!');
    return false;
  } catch (error) {
    console.log('✅ ATTACK BLOCKED!');
    console.log('Protection: Nonce Uniqueness Check');
    console.log('Reason:', error.message);
    console.log('\nThe system detected that this nonce was already used.');
    console.log('Each message must have a unique nonce - replays are rejected.\n');
    return true;
  }
}

/**
 * Demonstrate replay attack - old timestamp
 */
async function demonstrateOldMessageReplay() {
  console.log('\n=== STEP 3: REPLAY ATTACK - OLD MESSAGE ===\n');

  const sessionKey = await generateAESKey();
  const message = "Transfer $1000 to attacker";
  const iv = generateIV();
  const nonce = generateNonce();
  const oldTimestamp = Date.now() - (15 * 60 * 1000); // 15 minutes ago
  const sequenceNumber = 1;

  console.log('🔴 ATTACKER replays a message from 15 minutes ago');
  console.log('Message timestamp:', new Date(oldTimestamp).toISOString());
  console.log('Current time:', new Date().toISOString());
  console.log('Message age: 15 minutes (max allowed: 10 minutes)');

  const { ciphertext, authTag } = await encryptAES(sessionKey, message, iv);

  const oldMessageData = {
    messageId: 'old-message',
    nonce,
    timestamp: oldTimestamp,
    sequenceNumber,
    ciphertext,
    authTag,
    iv: arrayBufferToBase64(iv),
  };

  console.log('\n🔴 ATTACKER attempts to replay old message...\n');

  await new Promise(resolve => setTimeout(resolve, 500));

  try {
    await validateMessage(oldMessageData, sessionKey);
    console.log('❌ SECURITY FAILURE: Old message replay succeeded!');
    return false;
  } catch (error) {
    console.log('✅ ATTACK BLOCKED!');
    console.log('Protection: Timestamp Freshness Validation');
    console.log('Reason:', error.message);
    console.log('\nThe system only accepts messages within a 10-minute window.');
    console.log('This prevents attackers from replaying old captured messages.\n');
    return true;
  }
}

/**
 * Demonstrate replay attack - future timestamp
 */
async function demonstrateFutureMessageReplay() {
  console.log('\n=== STEP 4: REPLAY ATTACK - FUTURE TIMESTAMP ===\n');

  const sessionKey = await generateAESKey();
  const message = "Malicious message";
  const iv = generateIV();
  const nonce = generateNonce();
  const futureTimestamp = Date.now() + (5 * 60 * 1000); // 5 minutes in future
  const sequenceNumber = 1;

  console.log('🔴 ATTACKER creates message with future timestamp');
  console.log('Message timestamp:', new Date(futureTimestamp).toISOString());
  console.log('Current time:', new Date().toISOString());
  console.log('Time difference: +5 minutes (max allowed: +1 minute for clock skew)');

  const { ciphertext, authTag } = await encryptAES(sessionKey, message, iv);

  const futureMessageData = {
    messageId: 'future-message',
    nonce,
    timestamp: futureTimestamp,
    sequenceNumber,
    ciphertext,
    authTag,
    iv: arrayBufferToBase64(iv),
  };

  console.log('\n🔴 ATTACKER attempts to send message with future timestamp...\n');

  await new Promise(resolve => setTimeout(resolve, 500));

  try {
    await validateMessage(futureMessageData, sessionKey);
    console.log('❌ SECURITY FAILURE: Future timestamp attack succeeded!');
    return false;
  } catch (error) {
    console.log('✅ ATTACK BLOCKED!');
    console.log('Protection: Timestamp Validation');
    console.log('Reason:', error.message);
    console.log('\nThe system rejects messages with timestamps too far in the future.');
    console.log('This prevents timestamp manipulation attacks.\n');
    return true;
  }
}

/**
 * Demonstrate replay attack - sequence number violation
 */
async function demonstrateSequenceReplay() {
  console.log('\n=== STEP 5: REPLAY ATTACK - OUT OF ORDER ===\n');

  const sessionKey = await generateAESKey();
  const messageId = 'sequence-test';

  // Send message with sequence 5
  console.log('Bob has already received messages with sequence numbers: 1, 2, 3, 4, 5');
  processedMessages.set(messageId, 5);

  // Attacker tries to replay message with sequence 3
  const message = "Old message";
  const iv = generateIV();
  const nonce = generateNonce();
  const timestamp = Date.now();
  const oldSequence = 3;

  console.log('\n🔴 ATTACKER replays message with old sequence number');
  console.log('Message sequence:', oldSequence);
  console.log('Expected sequence: > 5');

  const { ciphertext, authTag } = await encryptAES(sessionKey, message, iv);

  const sequenceMessageData = {
    messageId,
    nonce,
    timestamp,
    sequenceNumber: oldSequence,
    ciphertext,
    authTag,
    iv: arrayBufferToBase64(iv),
  };

  console.log('\n🔴 ATTACKER attempts to replay out-of-order message...\n');

  await new Promise(resolve => setTimeout(resolve, 500));

  try {
    await validateMessage(sequenceMessageData, sessionKey);
    console.log('❌ SECURITY FAILURE: Out-of-order replay succeeded!');
    return false;
  } catch (error) {
    console.log('✅ ATTACK BLOCKED!');
    console.log('Protection: Sequence Number Monotonicity Check');
    console.log('Reason:', error.message);
    console.log('\nThe system tracks sequence numbers and rejects messages');
    console.log('with sequence numbers less than or equal to the last processed.\n');
    return true;
  }
}

/**
 * Generate comprehensive report
 */
function generateReport(results) {
  const timestamp = new Date().toISOString();
  const allBlocked = results.every(r => r.blocked);

  return `
# Replay Attack Demonstration Report

**Date:** ${timestamp}

## Executive Summary

This report documents replay attack demonstrations on the secure messaging system.
All ${results.length} attack scenarios were tested.

**Overall Result:** ${allBlocked ? '✅ ALL ATTACKS BLOCKED' : '❌ VULNERABILITIES DETECTED'}

## What is a Replay Attack?

A replay attack occurs when an attacker intercepts a valid encrypted message and 
attempts to resend it later. Even though the attacker cannot decrypt the message,
replaying it can cause:

- Duplicate transactions (e.g., "send $100" executed twice)
- Message confusion and ordering issues
- Unauthorized actions being repeated

## Attack Scenarios Tested

${results.map((r, i) => `
### Scenario ${i + 1}: ${r.name}

**Result:** ${r.blocked ? '✅ BLOCKED' : '❌ SUCCEEDED'}

**Description:** ${r.description}

**Protection Mechanism:** ${r.protection}

${r.blocked ? '✅ The attack was successfully detected and blocked.' : '❌ CRITICAL: This attack succeeded!'}
`).join('\n')}

## Protection Mechanisms

Our system implements three layers of replay attack protection:

### 1. Nonce Uniqueness Validation

Each message includes a cryptographically random nonce (number used once).
The system maintains a set of used nonces and rejects any duplicate.

**Implementation:**
\`\`\`javascript
if (usedNonces.has(nonce)) {
  throw new Error('Duplicate nonce - replay attack detected!');
}
usedNonces.add(nonce);
\`\`\`

### 2. Timestamp Freshness Check

Messages include a timestamp. The system only accepts messages within a 
10-minute window, rejecting messages that are too old or from the future.

**Implementation:**
\`\`\`javascript
const messageAge = Date.now() - timestamp;
const maxAge = 10 * 60 * 1000; // 10 minutes

if (messageAge > maxAge) {
  throw new Error('Message too old - replay attack detected!');
}
\`\`\`

### 3. Sequence Number Monotonicity

Messages between two parties are assigned monotonically increasing sequence 
numbers. The receiver tracks the last sequence number and rejects any message
with an equal or lower number.

**Implementation:**
\`\`\`javascript
if (sequenceNumber <= lastSequenceNumber) {
  throw new Error('Invalid sequence - replay attack detected!');
}
\`\`\`

## Test Results Summary

| Scenario | Protection | Result |
|----------|-----------|--------|
${results.map(r => `| ${r.name} | ${r.protection} | ${r.blocked ? '✅ Blocked' : '❌ Failed'} |`).join('\n')}

## Conclusion

${allBlocked
      ? 'The secure messaging system successfully demonstrated resilience against all replay attack scenarios through multiple layers of protection. The combination of nonce validation, timestamp checking, and sequence number tracking provides comprehensive defense against replay attacks.'
      : 'CRITICAL: The system has vulnerabilities that allow replay attacks. Immediate remediation is required.'
    }

## Recommendations

1. **Nonce Management:** Implement efficient nonce storage with automatic cleanup
2. **Time Synchronization:** Ensure server and client clocks are synchronized
3. **Sequence Tracking:** Maintain persistent sequence number state per conversation
4. **Monitoring:** Log all replay attack attempts for security analysis
5. **Testing:** Regularly test replay protection mechanisms

---

*This report was automatically generated by the attack demonstration module.*
`;
}

/**
 * Run all demonstrations
 */
async function runAllDemonstrations() {
  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║                                                            ║');
  console.log('║          REPLAY ATTACK DEMONSTRATION                       ║');
  console.log('║          Secure Messaging System                           ║');
  console.log('║                                                            ║');
  console.log('╚════════════════════════════════════════════════════════════╝');

  const results = [];

  try {
    // Normal message
    const { messageData, sessionKey } = await demonstrateNormalMessage();

    // Attack 1: Exact replay
    const blocked1 = await demonstrateExactReplay(messageData, sessionKey);
    results.push({
      name: 'Exact Message Replay',
      description: 'Attacker replays the exact same message with identical nonce',
      protection: 'Nonce Uniqueness Check',
      blocked: blocked1,
    });

    // Attack 2: Old message
    const blocked2 = await demonstrateOldMessageReplay();
    results.push({
      name: 'Old Message Replay',
      description: 'Attacker replays a message from 15 minutes ago',
      protection: 'Timestamp Freshness Validation',
      blocked: blocked2,
    });

    // Attack 3: Future timestamp
    const blocked3 = await demonstrateFutureMessageReplay();
    results.push({
      name: 'Future Timestamp Attack',
      description: 'Attacker sends message with timestamp 5 minutes in the future',
      protection: 'Timestamp Validation',
      blocked: blocked3,
    });

    // Attack 4: Sequence number
    const blocked4 = await demonstrateSequenceReplay();
    results.push({
      name: 'Out-of-Order Replay',
      description: 'Attacker replays message with old sequence number',
      protection: 'Sequence Number Monotonicity',
      blocked: blocked4,
    });

    // Summary
    console.log('\n╔════════════════════════════════════════════════════════════╗');
    console.log('║                    SUMMARY                                 ║');
    console.log('╚════════════════════════════════════════════════════════════╝\n');

    const totalTests = results.length;
    const blocked = results.filter(r => r.blocked).length;
    const failed = totalTests - blocked;

    console.log(`Total Attack Scenarios: ${totalTests}`);
    console.log(`✅ Blocked: ${blocked}`);
    console.log(`❌ Succeeded: ${failed}\n`);

    results.forEach((r, i) => {
      const icon = r.blocked ? '✅' : '❌';
      console.log(`${icon} ${i + 1}. ${r.name}: ${r.blocked ? 'BLOCKED' : 'SUCCEEDED'}`);
    });

    console.log('\n' + '='.repeat(60));
    console.log(blocked === totalTests
      ? '✅ ALL REPLAY ATTACKS SUCCESSFULLY BLOCKED!'
      : '❌ SECURITY VULNERABILITIES DETECTED!');
    console.log('='.repeat(60) + '\n');

    // Generate report
    console.log(generateReport(results));

  } catch (error) {
    console.error('\n❌ Error during demonstration:', error);
    process.exit(1);
  }
}

// Run the demonstration
runAllDemonstrations().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
