/**
 * Security Logging with MongoDB Backend
 */

import api from '../config/api.js';

/**
 * Log a security event
 */
export async function logSecurityEvent(userId, eventType, description, severity = 'INFO', metadata = {}) {
  try {
    const logEntry = {
      eventType,
      eventDescription: description,
      severity,
      metadata,
    };
    
    // Log to console
    const severityEmoji = {
      INFO: 'ℹ️',
      WARNING: '⚠️',
      ERROR: '❌',
      CRITICAL: '🚨',
    };
    
    console.log(
      `${severityEmoji[severity] || '📝'} [${severity}] ${eventType}: ${description}`,
      metadata
    );
    
    // Store in backend
    await api.post('/logs', logEntry);
  } catch (error) {
    console.error('Failed to log security event:', error);
  }
}

/**
 * Log authentication attempt
 */
export async function logAuthAttempt(userId, success, method = 'email') {
  await logSecurityEvent(
    userId,
    success ? 'AUTH_SUCCESS' : 'AUTH_FAILED',
    `Authentication ${success ? 'successful' : 'failed'} using ${method}`,
    success ? 'INFO' : 'WARNING',
    { method }
  );
}

/**
 * Log message encryption/decryption
 */
export async function logMessageCrypto(userId, action, success, messageId) {
  await logSecurityEvent(
    userId,
    success ? `MESSAGE_${action.toUpperCase()}_SUCCESS` : `MESSAGE_${action.toUpperCase()}_FAILED`,
    `Message ${action} ${success ? 'successful' : 'failed'}`,
    success ? 'INFO' : 'ERROR',
    { messageId, action }
  );
}

/**
 * Log detected replay attack
 */
export async function logReplayAttack(userId, messageId, reason) {
  await logSecurityEvent(
    userId,
    'REPLAY_ATTACK_DETECTED',
    `Replay attack detected: ${reason}`,
    'CRITICAL',
    { messageId, reason }
  );
}

/**
 * Log invalid signature detection
 */
export async function logInvalidSignature(userId, messageId, senderId) {
  await logSecurityEvent(
    userId,
    'INVALID_SIGNATURE_DETECTED',
    `Invalid signature detected from claimed sender ${senderId}`,
    'CRITICAL',
    { messageId, senderId }
  );
}

/**
 * Log file encryption/decryption
 */
export async function logFileCrypto(userId, action, success, fileId, fileSize) {
  await logSecurityEvent(
    userId,
    success ? `FILE_${action.toUpperCase()}_SUCCESS` : `FILE_${action.toUpperCase()}_FAILED`,
    `File ${action} ${success ? 'successful' : 'failed'} (${fileSize} bytes)`,
    success ? 'INFO' : 'ERROR',
    { fileId, fileSize, action }
  );
}

/**
 * Get security logs for a user
 */
export async function getSecurityLogs(userId, limit = 100) {
  try {
    const response = await api.get(`/logs?limit=${limit}`);
    return response.data.map(log => ({
      id: log._id,
      user_id: log.userId,
      event_type: log.eventType,
      event_description: log.eventDescription,
      severity: log.severity,
      metadata: log.metadata,
      created_at: log.createdAt,
    }));
  } catch (error) {
    console.error('Error fetching security logs:', error);
    return [];
  }
}

