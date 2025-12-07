import { useState } from 'react';
import { loginUser, loginAsGuest } from '../utils/auth-mongo';
import '../modern-login.css';

function Login({ onSuccess, onToggle }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await loginUser(email, password);
      onSuccess();
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-container-modern">
      {/* Main Content */}
      <div className="auth-content">
        <div className="auth-badge">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M8 0L10.5 5.5L16 8L10.5 10.5L8 16L5.5 10.5L0 8L5.5 5.5L8 0Z" fill="currentColor" />
          </svg>
          End-to-End Encrypted
        </div>

        <h1 className="auth-title">
          Welcome Back
        </h1>
        <p className="auth-subtitle">
          Sign in to your secure chat account
        </p>

        {error && <div className="error-message">{error}</div>}

        <form className="auth-form-modern" onSubmit={handleSubmit}>
          <div className="form-group-modern">
            <label>Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              placeholder="you@example.com"
              autoComplete="email"
            />
          </div>

          <div className="form-group-modern">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              placeholder="Enter your password"
              autoComplete="current-password"
            />
          </div>

          <button type="submit" className="btn-primary-modern" disabled={loading}>
            {loading ? (
              <>
                <span className="btn-spinner"></span>
                Logging in...
              </>
            ) : (
              <>
                Login
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M3 8H13M13 8L9 4M13 8L9 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </>
            )}
          </button>
        </form>

        <div className="guest-login-section" style={{ marginTop: '15px', textAlign: 'center' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '15px 0',
            color: 'rgba(255,255,255,0.3)',
            fontSize: '12px'
          }}>
            <span style={{ height: '1px', width: '30px', background: 'currentColor', marginRight: '10px' }}></span>
            OR
            <span style={{ height: '1px', width: '30px', background: 'currentColor', marginLeft: '10px' }}></span>
          </div>

          <button
            type="button"
            className="btn-secondary-modern"
            onClick={async () => {
              setError('');
              setLoading(true);
              try {
                await loginAsGuest();
                onSuccess();
              } catch (err) {
                setError(err.message || 'Guest login failed');
                setLoading(false);
              }
            }}
            disabled={loading}
            style={{
              background: 'rgba(255, 255, 255, 0.1)',
              border: '1px solid rgba(255, 255, 255, 0.2)',
              width: '100%',
              padding: '12px',
              borderRadius: '8px',
              color: 'white',
              cursor: 'pointer',
              transition: 'all 0.2s',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px'
            }}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M8 8C10.21 8 12 6.21 12 4C12 1.79 10.21 0 8 0C5.79 0 4 1.79 4 4C4 6.21 5.79 8 8 8ZM8 10C5.33 10 0 11.34 0 14V16H16V14C16 11.34 10.67 10 8 10Z" fill="currentColor" fillOpacity="0.7" />
            </svg>
            Sign in as Guest
          </button>
        </div>

        <div className="toggle-link-modern">
          Don't have an account?{' '}
          <button onClick={onToggle}>Create one</button>
        </div>

        <div className="auth-features">
          <div className="feature-item">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <path d="M10 2L12.5 7.5L18 10L12.5 12.5L10 18L7.5 12.5L2 10L7.5 7.5L10 2Z" fill="currentColor" />
            </svg>
            <span>AES-256-GCM Encryption</span>
          </div>
          <div className="feature-item">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <path d="M10 2L12.5 7.5L18 10L12.5 12.5L10 18L7.5 12.5L2 10L7.5 7.5L10 2Z" fill="currentColor" />
            </svg>
            <span>ECDH Key Exchange</span>
          </div>
          <div className="feature-item">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <path d="M10 2L12.5 7.5L18 10L12.5 12.5L10 18L7.5 12.5L2 10L7.5 7.5L10 2Z" fill="currentColor" />
            </svg>
            <span>Digital Signatures</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;
