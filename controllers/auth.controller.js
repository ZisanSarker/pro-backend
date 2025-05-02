const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const generateTokens = require('../utils/generateTokens');
const validator = require('validator');
require('colors');

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

  if (password.length < 6 || !/\d/.test(password) || !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return res.status(400).json({ message: 'Password must be at least 6 characters, include a number and special character' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username, email, password: hashedPassword });

    const { accessToken, refreshToken } = generateTokens(newUser._id);

    res.cookie('accessToken', accessToken, cookieOptions(15 * 60 * 1000));
    res.cookie('refreshToken', refreshToken, cookieOptions(7 * 24 * 60 * 60 * 1000));

    console.log(`✅ Registered: ${email}`.green.bold);

    res.status(201).json({
      message: 'Registered successfully',
      user: sanitizeUser(newUser),
    });
  } catch (err) {
    console.error(`❌ Register Error: ${err.message}`.red.bold);
    res.status(500).json({ message: 'Server error' });
  }
};

// ─────────── Login ───────────
exports.login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Please provide both email and password' });

  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const { accessToken, refreshToken } = generateTokens(user._id);

    res.cookie('accessToken', accessToken, cookieOptions(15 * 60 * 1000));
    res.cookie('refreshToken', refreshToken, cookieOptions(7 * 24 * 60 * 60 * 1000));

    console.log(`🔓 Logged in: ${email}`.blue.bold);

    res.status(200).json({
      message: 'Logged in successfully',
      user: sanitizeUser(user),
    });
  } catch (err) {
    console.error(`❌ Login Error: ${err.message}`.red.bold);
    res.status(500).json({ message: 'Server error' });
  }
};

// ─────────── Logout ───────────
exports.logout = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    if (user) {
      console.log(`🔒 Logged out: ${user.email}`.yellow.bold);
    } else {
      console.log(`🔒 Logged out user ID: ${req.userId}`.yellow.bold);
    }

    res.status(200).json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error(`❌ Logout Error: ${err.message}`.red.bold);
    res.status(500).json({ message: 'Server error' });
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
    console.error(`❌ Refresh Token Error: ${err.message}`.red.bold);
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
    console.error(`❌ Get User Error: ${err.message}`.red.bold);
    res.status(500).json({ message: 'Server error' });
  }
};
