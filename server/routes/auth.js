import express from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import SecurityLog from '../models/SecurityLog.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// Register
router.post('/register', async (req, res) => {
  try {
    console.log('📝 Registration request received');
    const { email, password, username, publicKeyECDH, publicKeySign } = req.body;
    
    console.log('Data:', { email, username, hasPassword: !!password, hasKeys: !!(publicKeyECDH && publicKeySign) });
    
    // Check if user exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      console.log('❌ User already exists');
      return res.status(400).json({ error: 'User already exists' });
    }
    
    console.log('✓ User does not exist, creating...');
    
    // Create user
    const user = new User({
      email,
      password,
      username,
      publicKeyECDH,
      publicKeySign,
    });
    
    console.log('✓ User object created, saving...');
    await user.save();
    console.log('✓ User saved to database');
    
    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '7d',
    });
    
    console.log('✓ JWT token generated');
    
    // Log registration
    await SecurityLog.create({
      userId: user._id,
      eventType: 'USER_REGISTERED',
      eventDescription: `User registered: ${username}`,
      severity: 'INFO',
      metadata: { email, username },
    });
    
    console.log('✅ Registration successful');
    
    res.status(201).json({
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
      },
      token,
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      await SecurityLog.create({
        eventType: 'AUTH_FAILED',
        eventDescription: `Login failed for email: ${email}`,
        severity: 'WARNING',
        metadata: { email },
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      await SecurityLog.create({
        userId: user._id,
        eventType: 'AUTH_FAILED',
        eventDescription: `Invalid password attempt`,
        severity: 'WARNING',
        metadata: { email },
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '7d',
    });
    
    // Log successful login
    await SecurityLog.create({
      userId: user._id,
      eventType: 'AUTH_SUCCESS',
      eventDescription: 'User logged in successfully',
      severity: 'INFO',
      metadata: { email },
    });
    
    res.json({
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
      },
      token,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get current user
router.get('/me', authenticate, async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        email: req.user.email,
        username: req.user.username,
        publicKeyECDH: req.user.publicKeyECDH,
        publicKeySign: req.user.publicKeySign,
      },
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;

