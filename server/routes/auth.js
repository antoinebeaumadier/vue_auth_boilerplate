const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const { signupValidation, signinValidation, validate } = require('../middleware/validators');
const { rateLimiters } = require('../middleware/security');
const logger = require('../middleware/logger');
const errorHandler = require('../middleware/errorHandler');
const prisma = new PrismaClient();
const PasswordValidator = require('password-validator');

// Validate required environment variables
if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
  throw new Error('JWT_SECRET and REFRESH_TOKEN_SECRET environment variables are required');
}

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

// Password validation schema
const passwordSchema = new PasswordValidator();
passwordSchema
  .is().min(8)
  .is().max(100)
  .has().uppercase()
  .has().lowercase()
  .has().digits()
  .has().symbols()
  .has().not().spaces()
  .is().not().oneOf(['Passw0rd', 'Password123']);

// Apply middleware
router.use(logger);

// Generate tokens
const generateTokens = async (user) => {
  const accessToken = jwt.sign(
    { userId: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { userId: user.id },
    REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );

  // Store refresh token in database
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      userId: user.id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
    }
  });

  return { accessToken, refreshToken };
};

// Middleware to verify JWT token
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token is required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId }
    });

    if (!user) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Sign up endpoint with sensitive rate limiting
router.post('/signup', rateLimiters.sensitive, signupValidation, validate, async (req, res, next) => {
  try {
    const { email, password, name } = req.body;

    // Validate password strength
    const passwordValidation = passwordSchema.validate(password, { details: true });
    if (passwordValidation.length > 0) {
      return res.status(400).json({
        error: 'Password does not meet requirements',
        requirements: passwordValidation.map(rule => rule.message)
      });
    }

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name: name || null,
        isVerified: false,
        verificationToken: jwt.sign({ email }, JWT_SECRET, { expiresIn: '24h' })
      }
    });

    // Remove sensitive data
    const { password: _, verificationToken, ...userWithoutSensitiveData } = user;

    // Generate tokens
    const { accessToken, refreshToken } = await generateTokens(user);

    // Return user data and tokens
    res.status(201).json({
      message: 'User created successfully. Please check your email for verification.',
      user: userWithoutSensitiveData,
      accessToken,
      refreshToken
    });

  } catch (error) {
    next(error);
  }
});

// Sign in endpoint with sensitive rate limiting
router.post('/signin', rateLimiters.sensitive, signinValidation, validate, async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if user is verified
    if (!user.isVerified) {
      return res.status(403).json({ error: 'Please verify your email first' });
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Remove sensitive data
    const { password: _, ...userWithoutPassword } = user;

    // Generate tokens
    const { accessToken, refreshToken } = await generateTokens(user);

    // Return user data and tokens
    res.json({
      message: 'Sign in successful',
      user: userWithoutPassword,
      accessToken,
      refreshToken
    });

  } catch (error) {
    next(error);
  }
});

// Refresh token endpoint with standard rate limiting
router.post('/refresh-token', rateLimiters.standard, async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token is required' });
    }

    // Verify and decode refresh token
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    
    // Check if token exists in database
    const storedToken = await prisma.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true }
    });

    if (!storedToken || storedToken.expiresAt < new Date()) {
      return res.status(403).json({ error: 'Invalid or expired refresh token' });
    }

    // Delete used refresh token
    await prisma.refreshToken.delete({
      where: { id: storedToken.id }
    });

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = await generateTokens(storedToken.user);

    res.json({
      accessToken,
      refreshToken: newRefreshToken
    });

  } catch (error) {
    next(error);
  }
});

// Email verification endpoint with standard rate limiting
router.get('/verify-email/:token', rateLimiters.standard, async (req, res, next) => {
  try {
    const { token } = req.params;

    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user exists and is not already verified
    const user = await prisma.user.findUnique({
      where: { email: decoded.email }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isVerified) {
      return res.status(400).json({ error: 'Email already verified' });
    }

    // Update user verification status
    await prisma.user.update({
      where: { email: decoded.email },
      data: { isVerified: true }
    });

    res.json({ message: 'Email verified successfully' });

  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Verification token has expired' });
    }
    next(error);
  }
});

// Protected route example
router.get('/profile', authenticateToken, async (req, res, next) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
        isVerified: true
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    next(error);
  }
});

// Error handling middleware
router.use(errorHandler);

module.exports = router; 