# MongoDB Setup Guide

## ✅ Migration Complete! 

Your secure chat app now uses **MongoDB** instead of Supabase!

## What Changed:

- ✅ **Backend**: Express.js server with MongoDB
- ✅ **Authentication**: JWT tokens instead of Supabase Auth
- ✅ **Database**: MongoDB Atlas instead of PostgreSQL
- ✅ **Password Hashing**: bcrypt (10 rounds)
- ✅ **Same Security**: End-to-end encryption, ECDH key exchange, digital signatures

## Connection String Already Configured:

Your MongoDB connection string is already in `.env`:
```
mongodb+srv://hassanilyas299:Hassanilyas786@cluster0.64lu5xf.mongodb.net/secure-chat
```

## How to Run:

### Option 1: Run Frontend and Backend Together (Recommended)

```bash
npm run dev:all
```

This runs both:
- **Backend** on http://localhost:3001
- **Frontend** on http://localhost:5173

### Option 2: Run Separately

Terminal 1 (Backend):
```bash
npm run server
```

Terminal 2 (Frontend):
```bash
npm run dev
```

## Testing the Setup:

1. **Start the server**:
   ```bash
   npm run dev:all
   ```

2. **Open browser**: http://localhost:5173

3. **Register a new user** - Keys will be generated automatically

4. **Login and chat** - Everything works the same!

## MongoDB Collections:

Your database (`secure-chat`) has these collections:

### 1. **users**
- Stores user accounts (email, username, hashed password)
- Stores **public keys only** (ECDH + ECDSA)
- Private keys **never** sent to server!

### 2. **messages**
- Stores **encrypted messages only**
- Fields: encryptedContent, iv, authTag, nonce, signature
- No plaintext ever stored!

### 3. **files**
- Stores **encrypted files only**
- Files encrypted client-side before upload

### 4. **securitylogs**
- Audit trail of all security events
- Authentication attempts, encryption events, detected attacks

## API Endpoints:

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/me` - Get current user

### Messages
- `GET /api/messages/:otherUserId` - Get messages
- `POST /api/messages` - Send encrypted message

### Files
- `GET /api/files/:otherUserId` - Get shared files list
- `GET /api/files/download/:fileId` - Download encrypted file
- `POST /api/files` - Upload encrypted file

### Users
- `GET /api/users` - Get all users (contact list)
- `GET /api/users/:userId/keys` - Get user's public keys

### Security Logs
- `GET /api/logs` - Get security logs
- `POST /api/logs` - Create security log

## Security Features Preserved:

✅ **End-to-End Encryption** - AES-256-GCM  
✅ **Key Exchange** - ECDH with P-384 curve  
✅ **Digital Signatures** - ECDSA for authentication  
✅ **Replay Protection** - Nonces, timestamps, sequence numbers  
✅ **Private Key Storage** - IndexedDB only (never sent to server)  
✅ **Password Security** - bcrypt hashing with salt  

## Troubleshooting:

### Error: "ECONNREFUSED localhost:3001"
**Solution**: Backend is not running. Run `npm run server` in a separate terminal.

### Error: "MongoServerError: Authentication failed"
**Solution**: Check your MongoDB connection string in `.env` file.

### Can't see messages from other users
**Solution**: Make sure both frontend and backend are running!

## Environment Variables:

Your `.env` file should have:
```env
MONGODB_URI=mongodb+srv://hassanilyas299:Hassanilyas786@cluster0.64lu5xf.mongodb.net/secure-chat?retryWrites=true&w=majority
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-12345
PORT=3001
```

## MongoDB Indexes:

The app automatically creates these indexes for performance:
- messages: `{ senderId, receiverId, timestamp }`
- messages: `{ nonce }` (unique - prevents replay attacks)
- files: `{ senderId, receiverId, createdAt }`
- securitylogs: `{ userId, createdAt }`

## Viewing Your Data:

You can view your MongoDB data at:
https://cloud.mongodb.com/

Login and navigate to:
- Browse Collections → secure-chat database
- View users, messages, files, securitylogs

Remember: Messages and files are **encrypted**! You'll see ciphertext, not plaintext.

## Differences from Supabase:

| Feature | Supabase | MongoDB |
|---------|----------|---------|
| **Auth** | Built-in | Custom JWT |
| **Database** | PostgreSQL | MongoDB |
| **RLS** | Row Level Security | JWT middleware |
| **Real-time** | Built-in subscriptions | Polling (3 seconds) |
| **Storage** | Built-in | Database (Base64) |

## All Features Still Work:

✅ User registration with key generation  
✅ Secure login with JWT tokens  
✅ End-to-end encrypted messaging  
✅ Encrypted file sharing  
✅ Security logging  
✅ Replay attack protection  
✅ Digital signature verification  
✅ Session persistence  
✅ Real-time message updates (polling)  

---

**Ready to go!** Run `npm run dev:all` and start chatting securely! 🎉

