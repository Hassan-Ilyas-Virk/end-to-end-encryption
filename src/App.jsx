import { useState, useEffect } from 'react';
import { getCurrentUser } from './utils/auth-mongo';
import Login from './components/Login';
import Register from './components/Register';
import Chat from './components/Chat';
import './App.css';

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showRegister, setShowRegister] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    console.log('🚀 App starting...');
    checkUser();

    // Check auth status periodically
    const interval = setInterval(() => {
      const token = localStorage.getItem('authToken');
      if (!token && user) {
        setUser(null);
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [user]);

  async function checkUser() {
    try {
      console.log('🔍 Checking for existing user session...');
      const currentUser = await getCurrentUser();
      if (currentUser) {
        console.log('✅ User session active:', currentUser.email);
        setUser(currentUser);
      } else {
        console.log('❌ No active session');
        setUser(null);
      }
      setError(null);
    } catch (error) {
      console.error('❌ Error checking user:', error);
      if (error.message.includes('fetch')) {
        setError('Cannot connect to server. Make sure backend is running on port 3001.');
      }
      setUser(null);
    } finally {
      setLoading(false);
      console.log('✅ App loaded');
    }
  }

  if (loading) {
    return (
      <div className="app">
        <div className="app-content">
          <div className="glass-container fade-in" style={{ padding: '48px', textAlign: 'center' }}>
            <div className="loading">
              <div>Loading Secure Chat...</div>
              <div style={{ fontSize: '14px', marginTop: '10px', opacity: 0.7 }}>
                Checking connection to backend...
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="app">
        <div className="app-content">
          <div className="glass-container auth-container fade-in">
            <h2 style={{ color: '#ff6b6b' }}>Connection Error</h2>
            <div className="error-message">
              <p style={{ marginBottom: '10px' }}>{error}</p>
              <p style={{ fontSize: '14px', color: 'rgba(255, 255, 255, 0.6)' }}>
                Make sure the backend server is running:
              </p>
              <code style={{
                display: 'block',
                padding: '10px',
                background: 'rgba(0, 0, 0, 0.3)',
                borderRadius: '8px',
                marginTop: '10px',
                color: '#B19EEF',
                fontSize: '13px'
              }}>
                npm run server
              </code>
            </div>
            <button
              onClick={() => {
                setError(null);
                setLoading(true);
                checkUser();
              }}
              className="btn-primary"
            >
              Retry Connection
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="app">
        {/* Big Typography Background */}
        <div className="app-background-text">
          <div className="bg-text-line">SECURE</div>
          <div className="bg-text-line">CHAT</div>
          <div className="bg-text-line">E2EE</div>
        </div>

        <div className="app-content">
          <div className="glass-container fade-in">
            {showRegister ? (
              <Register
                onSuccess={() => {
                  setShowRegister(false);
                  checkUser();
                }}
                onToggle={() => setShowRegister(false)}
              />
            ) : (
              <Login
                onSuccess={checkUser}
                onToggle={() => setShowRegister(true)}
              />
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <Chat user={user} onLogout={() => setUser(null)} />
    </div>
  );
}

export default App;
