// ============================================================
// CAR REMINDER - CLOUD SERVER
// Node.js + Express + MongoDB + JWT Authentication
// Deploy to: Render.com or Railway.app (both free)
// ============================================================

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_change_me';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/car_reminder';

// ─────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────
app.use(cors());
app.use(bodyParser.json());

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ─────────────────────────────────────────
// MongoDB Connection
// ─────────────────────────────────────────
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

// ─────────────────────────────────────────
// SCHEMAS & MODELS
// ─────────────────────────────────────────

// User Schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  name: {
    type: String,
    required: true,
    trim: true
  }
}, { timestamps: true });

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Reminder Schema
const reminderSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    required: true,
    enum: ['ITP', 'INSURANCE', 'WARRANTY', 'SERVICE', 'OIL_CHANGE'],
    uppercase: true
  },
  date: {
    type: String, // Store as 'YYYY-MM-DD' string for simplicity
    required: true
  },
  notes: {
    type: String,
    default: ''
  },
  localId: {
    type: Number, // The ID from the local SQLite database (for sync)
    default: null
  }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Reminder = mongoose.model('Reminder', reminderSchema);

// ─────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  // Header format: "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, error: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'Invalid or expired token' });
    }
    req.user = user; // { userId, email }
    next();
  });
}

// ─────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', server: 'cloud', timestamp: new Date().toISOString() });
});

// ── POST /auth/register ── Create a new user account
app.post('/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      success: false,
      error: 'name, email, and password are required'
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      error: 'Password must be at least 6 characters'
    });
  }

  try {
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ success: false, error: 'Email already registered' });
    }

    const user = new User({ name, email, password });
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.status(201).json({
      success: true,
      data: {
        token,
        user: { id: user._id, name: user.name, email: user.email }
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /auth/login ── Login and get a token
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'email and password are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      data: {
        token,
        user: { id: user._id, name: user.name, email: user.email }
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── GET /auth/me ── Get current user info
app.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });
    res.json({ success: true, data: user });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────────────────
// REMINDER ROUTES (all require auth)
// ─────────────────────────────────────────

// ── GET /reminders ── Get all reminders for logged-in user
app.get('/reminders', authenticateToken, async (req, res) => {
  try {
    const reminders = await Reminder.find({ userId: req.user.userId }).sort({ date: 1 });
    res.json({ success: true, data: reminders });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── GET /reminders/:id ── Get a single reminder
app.get('/reminders/:id', authenticateToken, async (req, res) => {
  try {
    const reminder = await Reminder.findOne({
      _id: req.params.id,
      userId: req.user.userId
    });
    if (!reminder) return res.status(404).json({ success: false, error: 'Reminder not found' });
    res.json({ success: true, data: reminder });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /reminders ── Create a reminder in the cloud
app.post('/reminders', authenticateToken, async (req, res) => {
  const { title, type, date, notes, localId } = req.body;

  if (!title || !type || !date) {
    return res.status(400).json({
      success: false,
      error: 'title, type, and date are required'
    });
  }

  try {
    const reminder = new Reminder({
      userId: req.user.userId,
      title,
      type: type.toUpperCase(),
      date,
      notes: notes || '',
      localId: localId || null
    });

    await reminder.save();
    res.status(201).json({ success: true, data: reminder });
  } catch (err) {
    if (err.name === 'ValidationError') {
      return res.status(400).json({ success: false, error: err.message });
    }
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── PUT /reminders/:id ── Update a reminder
app.put('/reminders/:id', authenticateToken, async (req, res) => {
  const { title, type, date, notes } = req.body;

  try {
    const reminder = await Reminder.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      { title, type: type?.toUpperCase(), date, notes },
      { new: true, runValidators: true }
    );

    if (!reminder) {
      return res.status(404).json({ success: false, error: 'Reminder not found' });
    }

    res.json({ success: true, data: reminder });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── DELETE /reminders/:id ── Delete a reminder
app.delete('/reminders/:id', authenticateToken, async (req, res) => {
  try {
    const reminder = await Reminder.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.userId
    });

    if (!reminder) {
      return res.status(404).json({ success: false, error: 'Reminder not found' });
    }

    res.json({ success: true, message: 'Reminder deleted successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /reminders/sync ── Bulk sync from local server
// Send an array of reminders; server saves them with localId for deduplication
app.post('/reminders/sync', authenticateToken, async (req, res) => {
  const { reminders } = req.body;

  if (!Array.isArray(reminders)) {
    return res.status(400).json({ success: false, error: 'reminders must be an array' });
  }

  try {
    const results = [];

    for (const r of reminders) {
      // Check if already synced (by localId)
      let existing = null;
      if (r.localId) {
        existing = await Reminder.findOne({ userId: req.user.userId, localId: r.localId });
      }

      if (existing) {
        // Update existing
        existing.title = r.title;
        existing.type = r.type;
        existing.date = r.date;
        existing.notes = r.notes || '';
        await existing.save();
        results.push({ localId: r.localId, cloudId: existing._id, action: 'updated' });
      } else {
        // Create new
        const newReminder = new Reminder({
          userId: req.user.userId,
          title: r.title,
          type: r.type,
          date: r.date,
          notes: r.notes || '',
          localId: r.localId || null
        });
        await newReminder.save();
        results.push({ localId: r.localId, cloudId: newReminder._id, action: 'created' });
      }
    }

    res.json({ success: true, synced: results.length, data: results });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────────────────
// 404 Handler
// ─────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Route not found' });
});

// ─────────────────────────────────────────
// Start Server
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log('');
  console.log('☁️  Car Reminder CLOUD Server started!');
  console.log(`📍 Running at: http://localhost:${PORT}`);
  console.log('');
  console.log('Auth endpoints:');
  console.log('  POST /auth/register');
  console.log('  POST /auth/login');
  console.log('  GET  /auth/me');
  console.log('');
  console.log('Reminder endpoints (require Authorization header):');
  console.log('  GET    /reminders');
  console.log('  GET    /reminders/:id');
  console.log('  POST   /reminders');
  console.log('  PUT    /reminders/:id');
  console.log('  DELETE /reminders/:id');
  console.log('  POST   /reminders/sync');
  console.log('');
});
