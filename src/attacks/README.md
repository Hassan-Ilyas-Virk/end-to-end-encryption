# Attack Demonstration Scripts

This directory contains scripts to demonstrate various security attacks and how our system protects against them.

## Available Scripts

### 1. MITM Attack Demonstration (`mitmAttack.js`)

Demonstrates Man-in-the-Middle attacks on key exchange protocols.

**Run Command:**
```bash
# From the project root directory:
node src/attacks/mitmAttack.js

# OR from the src/attacks directory:
cd src/attacks
node mitmAttack.js
```

**What it demonstrates:**
- How MITM attacks work on unsigned Diffie-Hellman key exchange (attack succeeds)
- How digital signatures prevent MITM attacks (attack blocked)
- Generates a comprehensive report showing both scenarios

**Expected output:**
- Step-by-step demonstration of both attack scenarios
- Comparison summary
- Full markdown report with technical details

---

### 2. Replay Attack Demonstration (`replayAttack.js`)

Demonstrates replay attacks and protection mechanisms with simulated message data.

**Run Command:**
```bash
# From the project root directory:
node src/attacks/replayAttack.js

# OR from the src/attacks directory:
cd src/attacks
node replayAttack.js
```

**What it demonstrates:**
- Normal message transmission and validation
- **Scenario 1:** Exact message replay (duplicate nonce) - ✅ BLOCKED
- **Scenario 2:** Old message replay (15 minutes old) - ✅ BLOCKED
- **Scenario 3:** Future timestamp attack - ✅ BLOCKED
- **Scenario 4:** Out-of-order sequence replay - ✅ BLOCKED
- Generates a comprehensive report with protection mechanisms

**Expected output:**
- Step-by-step demonstration of 4 replay attack scenarios
- Shows how each protection mechanism works
- Summary table and full markdown report

**Protection Mechanisms Demonstrated:**
- ✓ Nonce uniqueness validation
- ✓ Timestamp freshness checking (10-minute window)
- ✓ Sequence number monotonicity

---

## Quick Reference

| Script | Command (from project root) | Command (from src/attacks) |
|--------|----------------------------|----------------------------|
| MITM Attack | `node src/attacks/mitmAttack.js` | `node mitmAttack.js` |
| Replay Attack | `node src/attacks/replayAttack.js` | `node replayAttack.js` |

## Technical Details

Both scripts have been configured to work in Node.js environment while maintaining compatibility with the browser-based application. The crypto utilities automatically detect the environment and use the appropriate Web Crypto API implementation.
