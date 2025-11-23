# Threat Modeling Document

## STRIDE Analysis for Secure Messaging System

This document provides a comprehensive threat analysis using the STRIDE methodology.

---

## 1. Spoofing Identity

### Threats

#### T1.1: User Impersonation During Registration
**Description**: Attacker registers with someone else's email address.  
**Severity**: Medium  
**Affected Component**: Registration system

**Mitigation**:
- Email verification through Supabase Auth
- Unique username constraints
- Security logging of all registration attempts

#### T1.2: Message Sender Spoofing
**Description**: Attacker sends message pretending to be another user.  
**Severity**: Critical  
**Affected Component**: Messaging system

**Mitigation**:
- Digital signatures (ECDSA) on all messages
- Signature verification before message processing
- Public key authentication via Supabase database

#### T1.3: Key Exchange Impersonation (MITM)
**Description**: Attacker intercepts key exchange and impersonates one party.  
**Severity**: Critical  
**Affected Component**: Key exchange protocol

**Mitigation**:
- ECDSA signatures on all key exchange messages
- Mutual authentication (both parties verify signatures)
- Nonce and timestamp validation
- Security logging of key exchange events

---

## 2. Tampering

### Threats

#### T2.1: Message Content Modification
**Description**: Attacker modifies encrypted message in transit or storage.  
**Severity**: High  
**Affected Component**: Message transmission/storage

**Mitigation**:
- AES-GCM provides authenticated encryption
- Authentication tags verify message integrity
- Digital signatures on message metadata
- Tampering attempts logged as security events

#### T2.2: Public Key Substitution
**Description**: Attacker replaces public keys in database.  
**Severity**: Critical  
**Affected Component**: User public keys in database

**Mitigation**:
- Row Level Security (RLS) policies in Supabase
- Keys can only be set during registration
- Public keys signed by user during key exchange
- Database audit logs

#### T2.3: Replay Message Tampering
**Description**: Attacker replays old messages or reorders them.  
**Severity**: High  
**Affected Component**: Message ordering and freshness

**Mitigation**:
- Sequence numbers ensure ordering
- Nonces prevent exact replay
- Timestamps ensure freshness
- All three checked before message processing

---

## 3. Repudiation

### Threats

#### T3.1: Message Sender Denial
**Description**: User denies sending a message.  
**Severity**: Medium  
**Affected Component**: Message attribution

**Mitigation**:
- Digital signatures provide non-repudiation
- Security logs track all message sending events
- Signature verification proves authorship
- Timestamps logged with all messages

#### T3.2: Key Exchange Denial
**Description**: User denies participating in key exchange.  
**Severity**: Low  
**Affected Component**: Key exchange sessions

**Mitigation**:
- Key exchange sessions logged in database
- Digital signatures on key exchange messages
- Timestamps and nonces logged
- Cannot be denied without private key compromise

---

## 4. Information Disclosure

### Threats

#### T4.1: Server-Side Message Reading
**Description**: Server operator attempts to read messages.  
**Severity**: Critical  
**Affected Component**: Message storage

**Mitigation**:
- End-to-end encryption (server never has session keys)
- Only ciphertext stored in database
- Session keys derived from ECDH (never transmitted)
- Private keys never leave client

#### T4.2: Network Eavesdropping
**Description**: Attacker intercepts network traffic.  
**Severity**: High  
**Affected Component**: Data in transit

**Mitigation**:
- HTTPS for all communications (Supabase requirement)
- End-to-end encryption even over HTTPS
- Only encrypted data transmitted
- Forward secrecy through ephemeral keys

#### T4.3: Client-Side Key Theft
**Description**: Malware on client device steals private keys.  
**Severity**: Critical  
**Affected Component**: IndexedDB key storage

**Mitigation**:
- Keys stored in browser's secure IndexedDB
- Same-origin policy prevents cross-site access
- Keys cleared on logout (optional)
- Device-specific keys (no cloud sync)

**Note**: This is the hardest threat to mitigate - requires trusted client device.

#### T4.4: Metadata Leakage
**Description**: Server sees who talks to whom and when.  
**Severity**: Low  
**Affected Component**: Message metadata

**Known Limitation**: System design requires server to know sender/receiver for routing.

**Partial Mitigation**:
- Timestamps encrypted
- Message sizes padded (future enhancement)
- Contact discovery limited

---

## 5. Denial of Service

### Threats

#### T5.1: Message Flooding
**Description**: Attacker sends large volume of messages.  
**Severity**: Medium  
**Affected Component**: Message processing

**Mitigation**:
- Supabase rate limiting
- Client-side throttling
- Security logging of excessive activity
- Row Level Security prevents unauthorized sends

#### T5.2: Large File Upload
**Description**: Attacker uploads very large encrypted files.  
**Severity**: Medium  
**Affected Component**: File storage

**Mitigation**:
- Supabase storage limits
- Client-side file size validation (recommended)
- Chunked upload for large files
- Storage quotas per user

#### T5.3: Replay Flood
**Description**: Attacker floods system with replayed messages.  
**Severity**: Low  
**Affected Component**: Replay protection system

**Mitigation**:
- All replay attempts rejected immediately
- Logged as critical security events
- No processing overhead for replayed messages
- Nonce set in memory (bounded)

---

## 6. Elevation of Privilege

### Threats

#### T6.1: Unauthorized Message Access
**Description**: User tries to read messages not intended for them.  
**Severity**: High  
**Affected Component**: Message access control

**Mitigation**:
- Row Level Security policies enforce access control
- Users can only query their own messages
- Even if accessed, messages are encrypted
- No session key without proper key exchange

#### T6.2: Admin Database Access
**Description**: Database admin tries to read user data.  
**Severity**: High  
**Affected Component**: Database security

**Mitigation**:
- All messages encrypted end-to-end
- Private keys never in database
- Admin can see metadata but not content
- Audit logs track admin access

#### T6.3: Key Storage Access
**Description**: Attacker tries to access another user's keys in IndexedDB.  
**Severity**: Critical  
**Affected Component**: IndexedDB key storage

**Mitigation**:
- Same-origin policy isolates storage
- Each user session has own browser context
- Keys partitioned by user ID
- Cross-site scripting (XSS) protections

---

## Risk Assessment Matrix

| Threat ID | Threat | Likelihood | Impact | Risk | Mitigated? |
|-----------|--------|------------|--------|------|------------|
| T1.1 | User Impersonation | Low | Medium | Low | ✅ Yes |
| T1.2 | Message Sender Spoofing | Low | Critical | High | ✅ Yes |
| T1.3 | Key Exchange MITM | Low | Critical | High | ✅ Yes |
| T2.1 | Message Tampering | Low | High | Medium | ✅ Yes |
| T2.2 | Public Key Substitution | Low | Critical | High | ✅ Yes |
| T2.3 | Replay Tampering | Medium | High | High | ✅ Yes |
| T3.1 | Message Sender Denial | Low | Medium | Low | ✅ Yes |
| T3.2 | Key Exchange Denial | Low | Low | Low | ✅ Yes |
| T4.1 | Server Message Reading | Medium | Critical | High | ✅ Yes |
| T4.2 | Network Eavesdropping | Medium | High | High | ✅ Yes |
| T4.3 | Client Key Theft | Low | Critical | High | ⚠️ Partial |
| T4.4 | Metadata Leakage | High | Low | Medium | ⚠️ Known Limitation |
| T5.1 | Message Flooding | Medium | Medium | Medium | ✅ Yes |
| T5.2 | Large File Upload | Low | Medium | Low | ✅ Yes |
| T5.3 | Replay Flood | Low | Low | Low | ✅ Yes |
| T6.1 | Unauthorized Access | Low | High | Medium | ✅ Yes |
| T6.2 | Admin Database Access | Low | High | Medium | ✅ Yes |
| T6.3 | Key Storage Access | Low | Critical | High | ✅ Yes |

---

## Security Controls Summary

### Cryptographic Controls
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key Exchange**: ECDH with P-384 curve
- **Digital Signatures**: ECDSA with P-384 curve and SHA-384
- **Key Derivation**: HKDF with SHA-256
- **Random Number Generation**: Crypto.getRandomValues()

### Access Controls
- **Authentication**: Supabase Auth with bcrypt password hashing
- **Authorization**: Row Level Security policies
- **Key Storage**: Client-side only (IndexedDB)
- **Session Management**: JWT tokens from Supabase

### Integrity Controls
- **Message Authentication**: AES-GCM authentication tags
- **Signature Verification**: ECDSA signatures on all messages
- **Replay Protection**: Nonces, timestamps, sequence numbers
- **Tamper Detection**: Signature verification failures logged

### Logging & Monitoring
- **Security Logs**: All security events logged to database
- **Event Types**: Auth, key exchange, encryption, attacks
- **Severity Levels**: INFO, WARNING, ERROR, CRITICAL
- **Audit Trail**: Immutable logs with timestamps

---

## Residual Risks

### 1. Client-Side Key Compromise
**Risk**: If user's device is compromised, private keys can be stolen.  
**Acceptance Rationale**: This is inherent to client-side encryption. Alternative (server-side keys) would be worse.  
**Recommendation**: User education on device security.

### 2. Metadata Leakage
**Risk**: Server knows who communicates with whom and when.  
**Acceptance Rationale**: Required for message routing in this architecture.  
**Recommendation**: Document as known limitation. Future enhancement: use mixnets or onion routing.

### 3. Initial Key Distribution
**Risk**: First public key exchange relies on server integrity.  
**Acceptance Rationale**: Trust-On-First-Use (TOFU) model is industry standard for this architecture.  
**Recommendation**: Future enhancement: implement key fingerprint verification (like Signal).

### 4. No Multi-Device Support
**Risk**: Keys are device-specific; no cross-device sync.  
**Acceptance Rationale**: Secure key sync requires additional infrastructure.  
**Recommendation**: Document as limitation. Future enhancement: implement secure key backup.

---

## Conclusion

The secure messaging system successfully mitigates the majority of identified threats through:
- Strong cryptographic primitives
- End-to-end encryption architecture
- Comprehensive signature-based authentication
- Multiple layers of replay protection
- Detailed security logging

Residual risks are documented and accepted as limitations of the current architecture, with recommendations for future enhancements.

---

**Last Updated**: November 2025  
**Next Review**: After security testing phase

