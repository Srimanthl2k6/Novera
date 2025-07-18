// ================================
// NOVERA - PRODUCTION-READY BACKEND
// "Error 404 : Developer Not needed"
// ================================

// Environment variable validation first
const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI'];
requiredEnvVars.forEach(envVar => {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
});

// Additional JWT secret validation
if (process.env.JWT_SECRET.length < 32) {
  console.error('JWT_SECRET must be at least 32 characters long');
  process.exit(1);
}

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const cron = require('node-cron');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 5000;

// Utility functions
const getClientIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress || 
         req.ip;
};

const escapeHtml = (text) => {
  if (!text) return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.toString().replace(/[&<>"']/g, (m) => map[m]);
};

// Request ID middleware
app.use((req, res, next) => {
  req.id = Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);
app.use('/api/auth', authLimiter);

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = process.env.CLIENT_URL 
      ? process.env.CLIENT_URL.split(',') 
      : ['http://localhost:3000'];
    
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Basic middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(mongoSanitize());

// MongoDB connection with enhanced error handling
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log('✅ MongoDB connected successfully');
    console.log('🚀 Novera Backend - "Error 404 : Developer Not needed"');
    
    // Initialize time series collection for analytics
    await initializeAnalyticsCollection();
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  }
};

// Initialize Analytics Time Series Collection
const initializeAnalyticsCollection = async () => {
  try {
    const db = mongoose.connection.db;
    const collections = await db.listCollections({ name: 'analytics' }).toArray();
    
    if (collections.length === 0) {
      await db.createCollection('analytics', {
        timeseries: {
          timeField: 'timestamp',
          metaField: 'pageId',
          granularity: 'hours'
        },
        expireAfterSeconds: 2592000 // 30 days
      });
      console.log('✅ Analytics time series collection created');
    } else {
      console.log('✅ Analytics collection already exists');
    }
  } catch (error) {
    console.error('❌ Error initializing analytics collection:', error);
  }
};

// Handle connection events
mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.warn('MongoDB disconnected');
});

// Connect to database
connectDB();

// User Schema with enhanced indexes
const UserSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    lowercase: true
  },
  password: { 
    type: String, 
    required: true,
    minlength: 8
  },
  role: { 
    type: String, 
    enum: ['admin', 'user'], 
    default: 'user' 
  },
  isActive: { 
    type: Boolean, 
    default: true 
  },
  lastLogin: { 
    type: Date 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Enhanced indexes
UserSchema.index({ email: 1 });
UserSchema.index({ username: 1 });
UserSchema.index({ email: 1, isActive: 1 });

// Landing Page Schema with validation
const LandingPageSchema = new mongoose.Schema({
  title: { 
    type: String, 
    required: true,
    trim: true,
    maxlength: 200
  },
  slug: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    maxlength: 100
  },
  components: [{ 
    type: mongoose.Schema.Types.Mixed,
    validate: {
      validator: function(v) {
        return Array.isArray(v) && v.length <= 50;
      },
      message: 'Too many components'
    }
  }],
  settings: {
    theme: { 
      type: String, 
      default: 'modern',
      enum: ['modern', 'classic', 'minimal', 'bold']
    },
    primaryColor: { 
      type: String, 
      default: '#6366f1',
      validate: {
        validator: function(v) {
          return /^#[0-9A-F]{6}$/i.test(v);
        },
        message: 'Invalid color format'
      }
    },
    secondaryColor: { 
      type: String, 
      default: '#f59e0b',
      validate: {
        validator: function(v) {
          return /^#[0-9A-F]{6}$/i.test(v);
        },
        message: 'Invalid color format'
      }
    },
    font: { 
      type: String, 
      default: 'Inter',
      enum: ['Inter', 'Roboto', 'Open Sans', 'Lato', 'Montserrat']
    }
  },
  createdBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    required: true
  },
  isPublished: { 
    type: Boolean, 
    default: false 
  },
  views: { 
    type: Number, 
    default: 0,
    min: 0
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Enhanced indexes
LandingPageSchema.index({ createdBy: 1 });
LandingPageSchema.index({ slug: 1 });
LandingPageSchema.index({ isPublished: 1 });
LandingPageSchema.index({ createdBy: 1, isPublished: 1 });
LandingPageSchema.index({ slug: 1, isPublished: 1 });

// Update the updatedAt field before saving
LandingPageSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Analytics Schema for Time Series Collection
const AnalyticsSchema = new mongoose.Schema({
  pageId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'LandingPage',
    required: true
  },
  event: { 
    type: String, 
    required: true,
    enum: ['view', 'click', 'submit', 'download']
  },
  data: { 
    type: mongoose.Schema.Types.Mixed,
    default: {},
    validate: {
      validator: function(v) {
        try {
          return JSON.stringify(v || {}).length <= 1000;
        } catch (e) {
          return false;
        }
      },
      message: 'Data object too large or invalid'
    }
  },
  timestamp: { 
    type: Date, 
    default: Date.now 
  },
  userAgent: { 
    type: String,
    maxlength: 500
  },
  ip: { 
    type: String,
    maxlength: 45
  }
}, {
  timeseries: {
    timeField: 'timestamp',
    metaField: 'pageId',
    granularity: 'hours'
  },
  collection: 'analytics'
});

const User = mongoose.model('User', UserSchema);
const LandingPage = mongoose.model('LandingPage', LandingPageSchema);
const Analytics = mongoose.model('Analytics', AnalyticsSchema);

// Enhanced file cleanup job
const cleanupOldFiles = async () => {
  try {
    const uploadsDir = path.join(__dirname, 'uploads');
    
    // Check if directory exists
    if (!fs.existsSync(uploadsDir)) {
      console.log('Uploads directory does not exist, skipping cleanup');
      return;
    }
    
    const files = fs.readdirSync(uploadsDir);
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    let cleanedCount = 0;
    
    for (const file of files) {
      try {
        const filePath = path.join(uploadsDir, file);
        const stats = fs.statSync(filePath);
        
        if (stats.mtime < thirtyDaysAgo) {
          fs.unlinkSync(filePath);
          cleanedCount++;
          console.log(`Cleaned up old file: ${file}`);
        }
      } catch (fileError) {
        console.error(`Error processing file ${file}:`, fileError);
      }
    }
    
    console.log(`File cleanup completed. Cleaned ${cleanedCount} files.`);
  } catch (error) {
    console.error('File cleanup error:', error);
  }
};

// Run cleanup daily at 2 AM in production
if (process.env.NODE_ENV === 'production') {
  cron.schedule('0 2 * * *', cleanupOldFiles);
}

// Enhanced file upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '');
    cb(null, uniqueSuffix + '-' + sanitizedName);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { 
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // Check file extension
    const allowedTypes = /jpeg|jpg|png|gif|webp|svg/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    // Prevent path traversal
    if (file.originalname.includes('..') || file.originalname.includes('/')) {
      return cb(new Error('Invalid filename'));
    }

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'Access token required',
      requestId: req.id
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ 
        success: false, 
        message: 'Invalid or expired token',
        requestId: req.id
      });
    }

    try {
      const user = await User.findById(decoded.userId).select('-password');
      if (!user || !user.isActive) {
        return res.status(403).json({ 
          success: false, 
          message: 'User not found or inactive',
          requestId: req.id
        });
      }

      req.user = { 
        userId: user._id, 
        username: user.username, 
        email: user.email, 
        role: user.role 
      };
      next();
    } catch (error) {
      console.error('Token verification error:', error, { requestId: req.id });
      return res.status(500).json({ 
        success: false, 
        message: 'Server error during authentication',
        requestId: req.id
      });
    }
  });
};

// Enhanced validation middleware
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(error => ({
        field: error.param,
        message: error.msg,
        value: error.value
      })),
      requestId: req.id
    });
  }
  next();
};

// Sanitize HTML content
const sanitizeHTML = (html) => {
  if (!html) return '';
  return xss(html, {
    whiteList: {
      h1: ['style'],
      h2: ['style'],
      h3: ['style'],
      p: ['style'],
      div: ['style'],
      span: ['style'],
      img: ['src', 'alt', 'style'],
      a: ['href', 'style'],
      button: ['style'],
      section: ['style']
    }
  });
};

// ================================
// HEALTH CHECK
// ================================

app.get('/health', async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.json({
      status: 'ok',
      app: 'Novera',
      tagline: 'Error 404 : Developer Not needed',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: 'connected',
      analytics: 'time-series',
      requestId: req.id
    });
  } catch (error) {
    res.status(503).json({
      status: 'error',
      app: 'Novera',
      message: 'Database connection failed',
      requestId: req.id
    });
  }
});

// ================================
// AUTH ROUTES
// ================================

// User registration
app.post('/api/auth/register', [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be 3-30 characters and contain only letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .withMessage('Password must be at least 8 characters with uppercase, lowercase, number, and special character')
], validateRequest, async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email or username already exists',
        requestId: req.id
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      message: 'Welcome to Novera! Account created successfully.',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      requestId: req.id
    });
  } catch (error) {
    console.error('Registration error:', error, { requestId: req.id });
    res.status(500).json({
      success: false,
      message: 'Server error during registration',
      requestId: req.id
    });
  }
});

// User login
app.post('/api/auth/login', [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email'),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
], validateRequest, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        requestId: req.id
      });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
        requestId: req.id
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Welcome back to Novera!',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      requestId: req.id
    });
  } catch (error) {
    console.error('Login error:', error, { requestId: req.id });
    res.status(500).json({
      success: false,
      message: 'Server error during login',
      requestId: req.id
    });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        lastLogin: user.lastLogin
      },
      requestId: req.id
    });
  } catch (error) {
    console.error('Get user error:', error, { requestId: req.id });
    res.status(500).json({
      success: false,
      message: 'Server error',
      requestId: req.id
    });
  }
});

// ================================
// LANDING PAGE ROUTES
// ================================

// Get all pages for user
app.get('/api/pages', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const pages = await LandingPage.find({ createdBy: req.user.userId })
      .select('-components') // Exclude components for list view
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await LandingPage.countDocuments({ createdBy: req.user.userId });

    res.json({
      success: true,
      pages,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalItems: total,
        itemsPerPage: limit
      },
      requestId: req.id
    });
  } catch (error) {
    console.error('Get pages error:', error, { requestId: req.id });
    res.status(500).json({
      success: false,
      message: 'Server error',
      requestId: req.id
    });
  }
});

// Get single page
app.get('/api/pages/:id', authenticateToken, async (req, res) => {
  try {
    const page = await LandingPage.findOne({
      _id: req.params.id,
      createdBy: req.user.userId
    });

    if (!page) {
      return res.status(404).json({
        success: false,
        message: 'Page not found',
        requestId: req.id
      });
    }

    res.json({
      success: true,
      page,
      requestId: req.id
    });
  } catch (error) {
    console.error('Get page error:', error, { requestId: req.id });
    res.status(500).json({
      success: false,
      message: 'Server error',
      requestId: req.id
    });
  }
});

// Create new page (Fixed race condition)
app.post('/api/pages', [
  authenticateToken,
  body('title')
    .trim()
  
