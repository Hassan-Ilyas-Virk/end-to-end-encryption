import { useState, useEffect, useRef } from 'react';
import { logoutUser, getAllUsers, getUserPrivateKeys, getUserPublicKeys } from '../utils/auth-mongo';
import { createSharedSession, getSessionKey } from '../utils/keyExchange';
import { encryptAndSendMessage, decryptMessageForDisplay, getMessages } from '../utils/messaging-mongo';
import { encryptAndUploadFile, downloadAndDecryptFile, triggerFileDownload, getSharedFiles, deleteEncryptedFile } from '../utils/fileSharing-mongo';
import { generateAESKey } from '../utils/crypto';
import { getSecurityLogs } from '../utils/securityLogger-mongo';
import { keysExist } from '../utils/keyStorage';
import KeySetup from './KeySetup';

function Chat({ user, onLogout }) {
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [messageText, setMessageText] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionKey, setSessionKey] = useState(null);
  const [sessionId, setSessionId] = useState(null);
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [logs, setLogs] = useState([]);
  const [hasKeys, setHasKeys] = useState(true);
  const [checkingKeys, setCheckingKeys] = useState(true);
  const messagesEndRef = useRef(null);
  const decryptedMessagesCache = useRef(new Map()); // Cache decrypted messages by ID

  useEffect(() => {
    checkUserKeys();
  }, []);

  useEffect(() => {
    if (hasKeys) {
      loadUsers();
      loadLogs();
    }
  }, [hasKeys]);

  async function checkUserKeys() {
    try {
      const exists = await keysExist(user.id);
      setHasKeys(exists);

      if (!exists) {
        console.warn('⚠️ Private keys not found in IndexedDB');
      }
    } catch (error) {
      console.error('Error checking keys:', error);
      setHasKeys(false);
    } finally {
      setCheckingKeys(false);
    }
  }

  function handleKeysGenerated() {
    setHasKeys(true);
    loadUsers();
    loadLogs();
  }

  useEffect(() => {
    if (selectedUser) {
      // Clear previous messages when switching users
      setMessages([]);
      setFiles([]);
      setSessionKey(null);
      setSessionId(null);

      // Clear decryption cache when switching users
      decryptedMessagesCache.current.clear();

      // Setup session first
      setupSession();
    }
  }, [selectedUser]);

  // Load messages when session key is ready
  useEffect(() => {
    if (sessionKey && selectedUser) {
      loadMessages();
      loadFiles();
    }
  }, [sessionKey, selectedUser]);

  // Auto-refresh messages every 5 seconds when chat is active
  useEffect(() => {
    if (sessionKey && selectedUser) {
      const interval = setInterval(() => {
        console.log('🔄 Auto-refreshing messages...');
        loadMessages();
        loadFiles();
      }, 5000); // Poll every 5 seconds

      return () => clearInterval(interval);
    }
  }, [sessionKey, selectedUser]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  async function loadUsers() {
    try {
      const allUsers = await getAllUsers();
      // Filter out current user
      const otherUsers = allUsers.filter(u => u.id !== user.id);
      setUsers(otherUsers);
    } catch (error) {
      console.error('Error loading users:', error);
    }
  }

  async function setupSession() {
    try {
      setLoading(true);

      console.log('🔑 Setting up encrypted session with', selectedUser.username);

      // Get my private keys
      const myKeys = await getUserPrivateKeys(user.id);

      // Get other user's public keys
      const otherKeys = await getUserPublicKeys(selectedUser.id);

      console.log('✓ Keys retrieved');

      // Create shared session using ECDH
      const newSessionId = await createSharedSession(
        user.id,
        selectedUser.id,
        myKeys.ecdhPrivateKey,
        otherKeys.ecdhPublicKey
      );

      const key = getSessionKey(newSessionId);

      if (!key) {
        throw new Error('Failed to create session key');
      }

      setSessionId(newSessionId);
      setSessionKey(key);

      console.log('✅ Shared session established, loading messages...');
    } catch (error) {
      console.error('Error setting up session:', error);
      alert('Failed to establish encrypted session: ' + error.message);
    } finally {
      setLoading(false);
    }
  }

  async function loadMessages() {
    try {
      if (!sessionKey) {
        console.log('⏳ No session key yet, waiting...');
        return;
      }

      console.log('📨 Loading messages with sessionId:', sessionId);
      const [messageData, fileData] = await Promise.all([
        getMessages(user.id, selectedUser.id),
        getSharedFiles(user.id, selectedUser.id)
      ]);

      console.log(`Found ${messageData.length} messages and ${fileData.length} files`);

      // Decrypt messages before displaying (with caching)
      const decryptedMessages = [];

      for (const msg of messageData) {
        // Check if message is already decrypted in cache
        if (decryptedMessagesCache.current.has(msg.id)) {
          decryptedMessages.push(decryptedMessagesCache.current.get(msg.id));
          continue;
        }

        // Decrypt new message
        try {
          // Get sender's public key for signature verification
          const senderKeys = await getUserPublicKeys(msg.sender_id);

          // Decrypt message (without replay protection for historical messages)
          const plaintext = await decryptMessageForDisplay(
            msg,
            sessionKey,
            senderKeys.ecdsaPublicKey
          );

          const decryptedMsg = {
            ...msg,
            type: 'message',
            decrypted_text: plaintext,
            decryption_success: true,
          };

          // Cache the decrypted message
          decryptedMessagesCache.current.set(msg.id, decryptedMsg);
          decryptedMessages.push(decryptedMsg);

          console.log(`✅ Decrypted NEW message: ${plaintext.substring(0, 30)}...`);
        } catch (decryptError) {
          console.error('❌ Failed to decrypt message:', msg.id, decryptError.message);
          // Still show the message but mark as undecryptable
          const failedMsg = {
            ...msg,
            type: 'message',
            decrypted_text: '[Message hidden - encryption keys have changed]',
            decryption_success: false,
          };

          // Cache failed decryption to avoid retrying
          decryptedMessagesCache.current.set(msg.id, failedMsg);
          decryptedMessages.push(failedMsg);
        }
      }

      // Add files as file messages
      const fileMessages = fileData.map(file => ({
        id: file.id,
        type: 'file',
        sender_id: file.sender_id,  // Already mapped correctly in getSharedFiles
        receiver_id: file.receiver_id,  // Already mapped correctly in getSharedFiles
        timestamp: file.timestamp,
        filename: file.filename,
        file_size: file.file_size,
        created_at: file.created_at,
      }));

      // Combine and sort by timestamp
      const allItems = [...decryptedMessages, ...fileMessages].sort(
        (a, b) => new Date(a.timestamp) - new Date(b.timestamp)
      );

      setMessages(allItems);
      setFiles(fileData); // Keep files state for reference
      console.log(`✅ Loaded ${allItems.length} items (${decryptedMessages.length} messages, ${fileMessages.length} files)`);
    } catch (error) {
      console.error('Error loading messages:', error);
    }
  }

  async function loadFiles() {
    // Files are now loaded with messages, but keep this for file operations
    try {
      const fileData = await getSharedFiles(user.id, selectedUser.id);
      setFiles(fileData);
    } catch (error) {
      console.error('Error loading files:', error);
    }
  }

  async function loadLogs() {
    try {
      const logData = await getSecurityLogs(user.id, 20);
      setLogs(logData);
    } catch (error) {
      console.error('Error loading logs:', error);
    }
  }

  async function handleSendMessage(e) {
    e.preventDefault();

    if (!messageText.trim() || !sessionKey || !selectedUser) return;

    const textToSend = messageText;
    setMessageText(''); // Clear input immediately for better UX

    try {
      setLoading(true);

      // Get sender's private key for signing
      const { ecdsaPrivateKey } = await getUserPrivateKeys(user.id);

      // Encrypt and send message
      await encryptAndSendMessage(
        user.id,
        selectedUser.id,
        textToSend,
        sessionKey,
        ecdsaPrivateKey
      );

      console.log('✅ Message sent successfully');

      // Reload messages immediately to show sent message
      await loadMessages();
      await loadLogs();
    } catch (error) {
      console.error('Error sending message:', error);
      alert('Failed to send message: ' + error.message);
      setMessageText(textToSend); // Restore text if failed
    } finally {
      setLoading(false);
    }
  }

  async function handleFileUpload(file) {
    if (!file || !sessionKey || !selectedUser) return;

    try {
      setUploading(true);
      setSelectedFile(file);

      await encryptAndUploadFile(
        file,
        user.id,
        selectedUser.id,
        sessionKey
      );

      setSelectedFile(null);
      await loadMessages(); // Reload messages to show the new file
      await loadLogs();
    } catch (error) {
      console.error('Error uploading file:', error);
      alert('Failed to upload file: ' + error.message);
      setSelectedFile(null);
    } finally {
      setUploading(false);
    }
  }

  async function handleDownloadFile(fileId, filename) {
    try {
      const fileData = await downloadAndDecryptFile(fileId, sessionKey, user.id);
      triggerFileDownload(fileData.data, filename);
      await loadLogs();
    } catch (error) {
      console.error('Error downloading file:', error);
      alert('Failed to download file: ' + error.message);
    }
  }

  async function handleDeleteFile(fileId) {
    if (!confirm('Are you sure you want to delete this file? This action cannot be undone.')) {
      return;
    }

    try {
      await deleteEncryptedFile(fileId, user.id);
      await loadMessages(); // Reload messages to remove the deleted file
      await loadLogs();
    } catch (error) {
      console.error('Error deleting file:', error);
      alert('Failed to delete file: ' + error.message);
    }
  }

  async function handleLogout() {
    try {
      await logoutUser();
      onLogout();
    } catch (error) {
      console.error('Error logging out:', error);
    }
  }

  function scrollToBottom() {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }

  function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  if (checkingKeys) {
    return (
      <div className="chat-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="loading-spinner">
          <div>Checking encryption keys...</div>
        </div>
      </div>
    );
  }

  if (!hasKeys) {
    return <KeySetup user={user} onComplete={handleKeysGenerated} />;
  }

  const username = user.profile?.username || user.email?.split('@')[0] || 'User';
  const initials = username.substring(0, 2).toUpperCase();

  return (
    <div className="chat-container">
      {/* Dashboard Header */}
      <div className="dashboard-header">
        <div className="dashboard-title">
          <h1>Secure Chat</h1>
          <div className="dashboard-subtitle">
            End-to-End Encrypted Messaging
          </div>
        </div>
        <div className="dashboard-user-section">
          <div className="header-user-info">
            <div className="header-user-avatar">{initials}</div>
            <div className="header-user-details">
              <div className="header-username">{username}</div>
              <div className="header-email">{user.email}</div>
            </div>
          </div>
          <button onClick={handleLogout} className="header-logout-btn">
            Logout
          </button>
        </div>
      </div>

      {/* Left Panel - Chats */}
      <div className="sidebar">
        <div className="sidebar-header">
          <h3>Active Chats ({users.length})</h3>
        </div>

        <div className="user-list">
          {users.map(u => {
            const userInitials = u.username.substring(0, 2).toUpperCase();
            return (
              <div
                key={u.id}
                className={`user-item ${selectedUser?.id === u.id ? 'active' : ''}`}
                onClick={() => setSelectedUser(u)}
              >
                <div className="user-item-avatar">{userInitials}</div>
                <div className="user-item-info">
                  <div className="user-item-name">{u.username}</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Center Panel - Chat */}
      <div className="chat-main">
        {selectedUser ? (
          <>
            <div className="chat-header">
              <div className="chat-header-info">
                <div className="chat-header-avatar">
                  {selectedUser.username.substring(0, 2).toUpperCase()}
                </div>
                <div className="chat-header-details">
                  <h3>{selectedUser.username}</h3>
                  <div className="chat-status">
                    {sessionKey ? 'End-to-End Encrypted' : 'Setting up encryption...'}
                  </div>
                </div>
              </div>
            </div>

            <div className="messages-container">
              {messages.length === 0 ? (
                <div className="empty-state">
                  <div>No messages yet</div>
                  <div style={{ fontSize: '14px', marginTop: '10px' }}>
                    Send a message to start chatting securely
                  </div>
                </div>
              ) : (
                messages.map(item => {
                  const isSent = item.sender_id === user.id;
                  const senderInitials = isSent
                    ? initials
                    : selectedUser.username.substring(0, 2).toUpperCase();

                  if (item.type === 'file') {
                    // Render file as a message
                    return (
                      <div
                        key={item.id}
                        className={`message ${isSent ? 'sent' : 'received'}`}
                      >
                        {!isSent && (
                          <div className="message-avatar">
                            {senderInitials}
                          </div>
                        )}
                        <div className="message-bubble file-message-bubble">
                          <div className="file-message-content">
                            <div className="file-message-icon"></div>
                            <div className="file-message-info">
                              <div className="file-message-name">{item.filename}</div>
                              <div className="file-message-size">{formatFileSize(item.file_size)}</div>
                            </div>
                          </div>
                          <div className="file-message-actions">
                            <button
                              onClick={() => handleDownloadFile(item.id, item.filename)}
                              className="file-download-btn"
                            >
                              Download
                            </button>
                          </div>
                          <div className="message-time">
                            {formatTime(item.timestamp)}
                          </div>
                        </div>
                        {isSent && (
                          <div className="message-avatar">
                            {senderInitials}
                          </div>
                        )}
                      </div>
                    );
                  } else {
                    // Render regular message
                    return (
                      <div
                        key={item.id}
                        className={`message ${isSent ? 'sent' : 'received'}`}
                      >
                        {!isSent && (
                          <div className="message-avatar">
                            {senderInitials}
                          </div>
                        )}
                        <div className="message-bubble">
                          <div className="message-text">
                            {item.decryption_success ? (
                              item.decrypted_text
                            ) : (
                              <span style={{ fontStyle: 'italic', opacity: 0.7 }}>
                                {item.decrypted_text}
                              </span>
                            )}
                          </div>
                          <div className="message-time">
                            {formatTime(item.timestamp)}
                          </div>
                        </div>
                        {isSent && (
                          <div className="message-avatar">
                            {senderInitials}
                          </div>
                        )}
                      </div>
                    );
                  }
                })
              )}
              <div ref={messagesEndRef} />
            </div>

            <div className="message-input-container">
              <form onSubmit={handleSendMessage} className="message-input-form">
                <input
                  type="file"
                  id="file-input"
                  className="file-input-hidden"
                  onChange={async (e) => {
                    const file = e.target.files[0];
                    if (file) {
                      await handleFileUpload(file);
                    }
                    // Reset input so same file can be selected again
                    e.target.value = '';
                  }}
                  disabled={!sessionKey || uploading}
                />
                <label htmlFor="file-input" className="file-attach-btn" title="Attach file">
                  <span>+</span>
                </label>
                <input
                  type="text"
                  className="message-input"
                  value={messageText}
                  onChange={(e) => setMessageText(e.target.value)}
                  placeholder="Type a message..."
                  disabled={!sessionKey || loading}
                />
                <button
                  type="submit"
                  className="send-btn"
                  disabled={!sessionKey || loading || !messageText.trim()}
                >
                  {loading ? 'Sending...' : 'Send'}
                </button>
              </form>
            </div>
          </>
        ) : (
          <div className="empty-state">
            <div>Select a contact to start chatting</div>
            <div style={{ fontSize: '14px', marginTop: '10px', color: '#999' }}>
              All messages are end-to-end encrypted
            </div>
          </div>
        )}
      </div>

      {/* Right Panel - Security Logs */}
      <div className="security-panel">
        <div className="security-panel-header">
          <h3>Security Logs</h3>
          <div className="security-badge">{logs.length}</div>
        </div>
        <div className="security-logs-list">
          {logs.length === 0 ? (
            <div className="security-empty">
              <div>No security events yet</div>
              <div style={{ fontSize: '11px', marginTop: '8px', opacity: 0.6 }}>
                Events will appear here as you use the app
              </div>
            </div>
          ) : (
            logs.slice(0, 20).map(log => (
              <div key={log.id} className={`security-log-item ${log.severity}`}>
                <div className="security-log-header">
                  <div className="security-log-type">{log.event_type}</div>
                  <div className="security-log-time">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </div>
                </div>
                <div className="security-log-desc">{log.event_description}</div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

export default Chat;

