/**
 * Replay Attack Demonstration
 * 
 * This script demonstrates how replay attacks work and how our system prevents them
 */

import { simulateReplayAttack, receiveAndDecryptMessage } from '../utils/messaging';
import { logSecurityEvent } from '../utils/securityLogger';

/**
 * Demonstrate a replay attack
 * This will attempt to replay a previously sent message
 * The system should detect and block it using nonce, timestamp, and sequence number checks
 * 
 * @param {Object} originalMessage - Original message data
 * @param {CryptoKey} sessionKey - Session key
 * @param {string} senderPublicKey - Sender's ECDSA public key
 * @param {string} receiverId - Receiver ID
 * @returns {Promise<Object>} Attack result
 */
export async function demonstrateReplayAttack(
  originalMessage,
  sessionKey,
  senderPublicKey,
  receiverId
) {
  console.log('\n=== REPLAY ATTACK DEMONSTRATION ===\n');
  
  console.log('Step 1: Original message was sent and received successfully');
  console.log('Message ID:', originalMessage.id);
  console.log('Nonce:', originalMessage.nonce);
  console.log('Timestamp:', new Date(originalMessage.timestamp).toISOString());
  console.log('Sequence Number:', originalMessage.sequence_number);
  
  console.log('\nStep 2: Attacker intercepts the encrypted message');
  console.log('Encrypted Content:', originalMessage.encrypted_content.substring(0, 50) + '...');
  console.log('Signature:', originalMessage.signature.substring(0, 50) + '...');
  
  console.log('\nStep 3: Attacker attempts to replay the same message');
  console.log('🔴 ATTACK IN PROGRESS...\n');
  
  // Wait a moment for dramatic effect
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  try {
    // Attempt to decrypt the same message again (simulating replay)
    await receiveAndDecryptMessage(
      originalMessage,
      sessionKey,
      senderPublicKey,
      receiverId
    );
    
    // If we get here, the attack succeeded (BAD!)
    console.log('❌ SECURITY FAILURE: Replay attack succeeded!');
    console.log('The system did not detect the replayed message.\n');
    
    await logSecurityEvent(
      receiverId,
      'REPLAY_ATTACK_SUCCEEDED',
      'CRITICAL SECURITY FAILURE: Replay attack was not blocked',
      'CRITICAL'
    );
    
    return {
      blocked: false,
      message: 'SECURITY VULNERABILITY: Replay attack succeeded',
      vulnerability: 'The system does not properly validate nonces, timestamps, or sequence numbers',
    };
  } catch (error) {
    // Attack blocked (GOOD!)
    console.log('✅ ATTACK BLOCKED: ' + error.message);
    console.log('\nProtection mechanisms that prevented the attack:');
    
    if (error.message.includes('nonce')) {
      console.log('  ✓ Nonce validation: Duplicate nonce detected');
    }
    if (error.message.includes('timestamp')) {
      console.log('  ✓ Timestamp validation: Message too old or from future');
    }
    if (error.message.includes('sequence')) {
      console.log('  ✓ Sequence number validation: Invalid sequence detected');
    }
    
    console.log('\n=== ATTACK DEMONSTRATION COMPLETE ===\n');
    
    await logSecurityEvent(
      receiverId,
      'REPLAY_ATTACK_BLOCKED',
      'Replay attack successfully blocked by protection mechanisms',
      'INFO',
      { reason: error.message }
    );
    
    return {
      blocked: true,
      message: 'Replay attack was successfully blocked',
      reason: error.message,
      protections: [
        'Nonce uniqueness check',
        'Timestamp freshness validation',
        'Sequence number monotonicity check',
      ],
    };
  }
}

/**
 * Test all replay attack scenarios
 * @param {Object} messageData - Message data
 * @param {CryptoKey} sessionKey - Session key
 * @param {string} senderPublicKey - Sender's public key
 * @param {string} receiverId - Receiver ID
 * @returns {Promise<Object>} Test results
 */
export async function testAllReplayScenarios(
  messageData,
  sessionKey,
  senderPublicKey,
  receiverId
) {
  console.log('\n=== COMPREHENSIVE REPLAY ATTACK TESTING ===\n');
  
  const results = {
    scenarios: [],
    passed: 0,
    failed: 0,
  };
  
  // Scenario 1: Exact replay (duplicate nonce)
  console.log('Scenario 1: Exact message replay');
  try {
    await receiveAndDecryptMessage(messageData, sessionKey, senderPublicKey, receiverId);
    results.scenarios.push({ name: 'Exact replay', blocked: false });
    results.failed++;
  } catch (error) {
    results.scenarios.push({ name: 'Exact replay', blocked: true, reason: error.message });
    results.passed++;
  }
  
  // Scenario 2: Modified timestamp (future date)
  console.log('\nScenario 2: Message with future timestamp');
  const futureMessage = {
    ...messageData,
    timestamp: Date.now() + 1000000, // Future timestamp
  };
  try {
    await receiveAndDecryptMessage(futureMessage, sessionKey, senderPublicKey, receiverId);
    results.scenarios.push({ name: 'Future timestamp', blocked: false });
    results.failed++;
  } catch (error) {
    results.scenarios.push({ name: 'Future timestamp', blocked: true, reason: error.message });
    results.passed++;
  }
  
  // Scenario 3: Old timestamp
  console.log('\nScenario 3: Message with old timestamp');
  const oldMessage = {
    ...messageData,
    timestamp: Date.now() - 20 * 60 * 1000, // 20 minutes old
  };
  try {
    await receiveAndDecryptMessage(oldMessage, sessionKey, senderPublicKey, receiverId);
    results.scenarios.push({ name: 'Old timestamp', blocked: false });
    results.failed++;
  } catch (error) {
    results.scenarios.push({ name: 'Old timestamp', blocked: true, reason: error.message });
    results.passed++;
  }
  
  console.log('\n=== TEST RESULTS ===');
  console.log(`Total scenarios: ${results.scenarios.length}`);
  console.log(`Passed (attacks blocked): ${results.passed}`);
  console.log(`Failed (attacks succeeded): ${results.failed}`);
  console.log('\nDetails:');
  results.scenarios.forEach(scenario => {
    const status = scenario.blocked ? '✅' : '❌';
    console.log(`${status} ${scenario.name}: ${scenario.blocked ? 'BLOCKED' : 'NOT BLOCKED'}`);
    if (scenario.reason) {
      console.log(`   Reason: ${scenario.reason}`);
    }
  });
  
  return results;
}

/**
 * Generate a report for the replay attack demonstration
 * @param {Object} attackResult - Result from demonstrateReplayAttack
 * @returns {string} Markdown report
 */
export function generateReplayAttackReport(attackResult) {
  const timestamp = new Date().toISOString();
  
  return `
# Replay Attack Demonstration Report

**Date:** ${timestamp}

## Executive Summary

This report documents the replay attack demonstration conducted on the secure messaging system.

## Attack Description

A replay attack involves an attacker intercepting an encrypted message and attempting to resend it at a later time. Even though the attacker cannot decrypt the message, they can potentially cause it to be processed again by the receiver, leading to:

- Duplicate transactions
- Confusion in message ordering
- Potential security vulnerabilities

## Attack Attempt

**Result:** ${attackResult.blocked ? '✅ BLOCKED' : '❌ SUCCEEDED'}

${attackResult.blocked ? `
### Protection Mechanisms

The following security mechanisms successfully prevented the replay attack:

${attackResult.protections.map(p => `- ${p}`).join('\n')}

**Reason for Blocking:** ${attackResult.reason}

### How It Works

1. **Nonce Validation:** Each message includes a unique nonce (random value). The system maintains a set of used nonces and rejects any message with a duplicate nonce.

2. **Timestamp Validation:** Messages include a timestamp. The system only accepts messages within a certain time window (10 minutes in our implementation), rejecting messages that are too old or from the future.

3. **Sequence Number Validation:** Messages between two parties are assigned monotonically increasing sequence numbers. The receiver tracks the last received sequence number and rejects any message with an equal or lower sequence number.

### Code Implementation

The replay protection is implemented in \`messaging.js\`:

\`\`\`javascript
// Check nonce uniqueness
if (usedNonces.has(nonce)) {
  throw new Error('REPLAY ATTACK: Duplicate nonce detected!');
}

// Check timestamp freshness
if (timeDiff > maxAge || timeDiff < -60000) {
  throw new Error('REPLAY ATTACK: Invalid timestamp!');
}

// Check sequence number
if (sequenceNumber <= lastSequenceNumber) {
  throw new Error('REPLAY ATTACK: Invalid sequence number!');
}
\`\`\`

` : `
### ⚠️ SECURITY VULNERABILITY DETECTED

The replay attack was **NOT** blocked. This indicates a critical security flaw in the system.

**Issue:** ${attackResult.message}

**Recommendation:** Implement proper replay protection mechanisms including:
- Nonce uniqueness validation
- Timestamp freshness checks
- Sequence number monotonicity checks
`}

## Conclusion

${attackResult.blocked
  ? 'The secure messaging system successfully demonstrated resilience against replay attacks through multiple layers of protection.'
  : 'CRITICAL: The system is vulnerable to replay attacks and requires immediate attention.'
}

## Recommendations

1. Continue monitoring for replay attack attempts in security logs
2. Periodically review and update the time window for timestamp validation
3. Implement nonce cleanup mechanisms to prevent memory exhaustion
4. Consider adding additional entropy sources for nonce generation

---

*This report was automatically generated by the attack demonstration module.*
`;
}

