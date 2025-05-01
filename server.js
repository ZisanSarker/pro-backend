const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const authRoutes = require('./routes/auth.routes');
require('dotenv').config();

// 👇 Import Passport strategy configuration
require('./config/passport');

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors())

// ✅ Add session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'superSecretKey', // make sure to store this in .env
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false, // set to true in production with HTTPS
    maxAge: 1000 * 60 * 60 * 24, // 1 day
  },
}));

// Passport.js setup
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// Routes
app.use('/auth', authRoutes);

app.get('/', (req, res) => {
  res.send('Welcome to the Pro-Backend Server');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
