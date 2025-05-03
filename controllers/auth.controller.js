const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const generateTokens = require('../utils/generateTokens');
const validator = require('validator');
const passport = require('../config/passport');
require('colors');

const cookieOptions = (maxAge) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge,
  path: '/'
});

const sanitizeUser = (user) => {
  const userObj = user.toJSON ? user.toJSON() : user.toObject();
  return userObj;
};


// ─────────── Register ───────────
exports.register = async (req, res) => {
  const { username, email, password } = req.body;

  // Basic validations
  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Please provide all required fields' });
  }

  if (!validator.isEmail(email)) {
    return res.status(400).json({ message: 'Invalid email address' });
  }

  if (password.length < 8 || !/\d/.test(password) || !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return res.status(400).json({ message: 'Password must be at least 8 characters, include a number and special character' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already exists' });

    // Create new user (password hashing handled by model pre-save hook)
    const newUser = await User.create({ username, email, password });

    const { accessToken, refreshToken } = generateTokens(newUser._id);

    res.cookie('accessToken', accessToken, cookieOptions(15 * 60 * 1000));
    res.cookie('refreshToken', refreshToken, cookieOptions(7 * 24 * 60 * 60 * 1000));

    console.log(`Registered: ${email}`.green.bold);

    res.status(201).json({
      message: 'Registered successfully',
      user: sanitizeUser(newUser)
    });
  } catch (err) {
    console.error(`Register Error: ${err.message}`.red.bold);
    res.status(500).json({ message: 'Server error during registration' });
  }
};

// ─────────── Login ───────────
exports.login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Please provide both email and password' });

  try {
    const user = await User.findOne({ email }).select('+password');
    
    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Update last login time
    user.lastLogin = Date.now();
    await user.save({ validateBeforeSave: false });

    const { accessToken, refreshToken } = generateTokens(user._id);

    res.cookie('accessToken', accessToken, cookieOptions(15 * 60 * 1000));
    res.cookie('refreshToken', refreshToken, cookieOptions(7 * 24 * 60 * 60 * 1000));

    console.log(`Logged in: ${email}`.blue.bold);

    res.status(200).json({
      message: 'Logged in successfully',
      user: sanitizeUser(user)
    });
  } catch (err) {
    console.error(`Login Error: ${err.message}`.red.bold);
    res.status(500).json({ message: 'Server error' });
  }
};

// ─────────── Logout ───────────
exports.logout = (req, res) => {
  try {
    // Clear JWT cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    // Passport logout (for OAuth session)
    req.logout((err) => {
      if (err) {
        console.error(`Logout Error: ${err.message}`.red.bold);
        return res.status(500).json({ message: 'Logout failed' });
      }

      // Log the event
      if (req.user?.email) {
        console.log(`Logged out: ${req.user.email}`.yellow.bold);
      } else if (req.userId) {
        console.log(`Logged out user ID: ${req.userId}`.yellow.bold);
      } else {
        console.log(`Logged out anonymous session`.yellow.bold);
      }

      // Send logout success response
      res.status(200).json({ message: 'Logged out successfully' });
    });
  } catch (err) {
    console.error(`❌ Logout Error: ${err.message}`.red.bold);
    res.status(500).json({ message: 'Server error during logout' });
  }
};


// ─────────── Refresh Token ───────────
exports.refreshToken = (req, res) => {
  const refreshTokenFromClient = req.cookies.refreshToken;

  if (!refreshTokenFromClient) {
    return res.status(403).json({ message: 'Refresh token required' });
  }

  try {
    const decoded = jwt.verify(refreshTokenFromClient, process.env.JWT_REFRESH_SECRET);
    const { accessToken, refreshToken } = generateTokens(decoded.userId);

    res.cookie('accessToken', accessToken, cookieOptions(15 * 60 * 1000));
    res.cookie('refreshToken', refreshToken, cookieOptions(7 * 24 * 60 * 60 * 1000));

    res.status(200).json({ message: 'Tokens refreshed successfully' });
  } catch (err) {
    console.error(`Refresh Token Error: ${err.message}`.red.bold);
    res.status(403).json({ message: 'Invalid refresh token' });
  }
};

// ─────────── Get Current User ───────────
exports.getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.status(200).json({ user });
  } catch (err) {
    console.error(`Get User Error: ${err.message}`.red.bold);
    res.status(500).json({ message: 'Server error' });
  }
};

// ─────────── oAuth 2.0 Google ───────────
exports.startGoogleAuth = passport.authenticate('google', {
  scope: ['profile', 'email'],
});
exports.handleGoogleCallback = [
  passport.authenticate('google', {
    failureRedirect: '/login',
  }),
  async (req, res) => {
    try {
      // User object is already set by passport
      const user = req.user;
      
      // Update last login
      user.lastLogin = Date.now();
      
      await user.save({ validateBeforeSave: false });

      // Generate JWT tokens
      const { accessToken, refreshToken } = generateTokens(user._id);
      // Set cookies
      res.cookie('accessToken', accessToken, cookieOptions(15 * 60 * 1000));
      res.cookie('refreshToken', refreshToken, cookieOptions(7 * 24 * 60 * 60 * 1000));

      console.log(`Logged in via Google: ${user.email}`.blue.bold);

      // Redirect to home or dashboard
      res.redirect(process.env.FRONTEND_URL || '/');
    } catch (err) {
      console.error(`Google Auth Error: ${err.message}`.red.bold);
    }
  }
];

// ─────────── oAuth 2.0 GitHub ───────────
exports.startGithubAuth = passport.authenticate('github', {
  scope: ['user:email'],
});

exports.handleGithubCallback = [
  passport.authenticate('github', {
    failureRedirect: '/login',
  }),
  async (req, res) => {
    try {
      const user = req.user;
      user.lastLogin = Date.now();
      await user.save({ validateBeforeSave: false });

      const { accessToken, refreshToken } = generateTokens(user._id);

      res.cookie('accessToken', accessToken, cookieOptions(15 * 60 * 1000));
      res.cookie('refreshToken', refreshToken, cookieOptions(7 * 24 * 60 * 60 * 1000));

      console.log(`Logged in via GitHub: ${user.email}`.cyan.bold);
      res.redirect(process.env.FRONTEND_URL || '/');
    } catch (err) {
      console.error(`GitHub Auth Error: ${err.message}`.red.bold);
    }
  },
];

// ─────────── oAuth 2.0 Facebook ───────────
exports.startFacebookAuth = passport.authenticate('facebook', {
  scope: ['email'],
});

exports.handleFacebookCallback = [
  passport.authenticate('facebook', {
    failureRedirect: '/login',
  }),
  async (req, res) => {
    try {
      const user = req.user;
      user.lastLogin = Date.now();
      await user.save({ validateBeforeSave: false });

      const { accessToken, refreshToken } = generateTokens(user._id);

      res.cookie('accessToken', accessToken, cookieOptions(15 * 60 * 1000));
      res.cookie('refreshToken', refreshToken, cookieOptions(7 * 24 * 60 * 60 * 1000));

      console.log(`Logged in via Facebook: ${user.email}`.magenta.bold);
      res.redirect(process.env.FRONTEND_URL || '/');
    } catch (err) {
      console.error(`Facebook Auth Error: ${err.message}`.red.bold);
    }
  },
];
