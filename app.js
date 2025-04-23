require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(cors({
  origin: '*',  // Allow all origins
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running' });
});
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch((err) => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Password Schema
const passwordSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  encryptedData: { type: String, required: true },  // Base64 encoded encrypted data
  iv: { type: String, required: true },            // Base64 encoded initialization vector
  lastModified: { type: Date, default: Date.now }
});

const Password = mongoose.model('Password', passwordSchema);

// Authentication Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization').replace('Bearer ', '');
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      throw new Error();
    }
    
    req.token = token;
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Please authenticate' });
  }
};

// Routes

// Check if email exists
app.post('/check-email', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    res.json({
      success: true,
      data: { exists: !!user }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error checking email',
      error: error.message
    });
  }
});

// Update user profile
app.put('/profile', auth, async (req, res) => {
  try {
    const updates = Object.keys(req.body);
    const allowedUpdates = ['name', 'email'];
    const isValidOperation = updates.every(update => allowedUpdates.includes(update));

    if (!isValidOperation) {
      return res.status(400).json({
        success: false,
        message: 'Invalid updates'
      });
    }

    updates.forEach(update => req.user[update] = req.body[update]);
    await req.user.save();

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: req.user
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating profile',
      error: error.message
    });
  }
});

// Verify password
app.post('/verify-password', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    res.json({
      success: isMatch,
      message: isMatch ? 'Password verified' : 'Invalid password'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error verifying password',
      error: error.message
    });
  }
});

// Update password
app.put('/password', auth, async (req, res) => {
  try {
    const { password } = req.body;
    req.user.password = await bcrypt.hash(password, 10);
    await req.user.save();

    res.json({
      success: true,
      message: 'Password updated successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating password',
      error: error.message
    });
  }
});

// Signup
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false, 
        message: 'User already exists' 
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = new User({
      email,
      password: hashedPassword
    });
    
    await user.save();
    
    // Generate token
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: { token }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error creating user',
      error: error.message
    });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      message: 'Login successful',
      data: { token }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error logging in',
      error: error.message
    });
  }
});

// Password Routes

// Get all passwords
app.get('/passwords', auth, async (req, res) => {
  try {
    const passwords = await Password.find({ userId: req.user._id });
    res.json({
      success: true,
      message: 'Passwords retrieved successfully',
      data: passwords
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error retrieving passwords',
      error: error.message
    });
  }
});

// Add new password
app.post('/passwords', auth, async (req, res) => {
  try {
    const password = new Password({
      ...req.body,
      userId: req.user._id
    });
    
    await password.save();
    
    res.status(201).json({
      success: true,
      message: 'Password saved successfully',
      data: password
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error saving password',
      error: error.message
    });
  }
});

// Update password
app.put('/passwords/:id', auth, async (req, res) => {
  try {
    const password = await Password.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { ...req.body, lastModified: Date.now() },
      { new: true }
    );
    
    if (!password) {
      return res.status(404).json({
        success: false,
        message: 'Password not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Password updated successfully',
      data: password
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error updating password',
      error: error.message
    });
  }
});

// Delete password
app.delete('/passwords/:id', auth, async (req, res) => {
  try {
    const password = await Password.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id
    });
    
    if (!password) {
      return res.status(404).json({
        success: false,
        message: 'Password not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Password deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error deleting password',
      error: error.message
    });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
