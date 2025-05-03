require('dotenv').config();
const passport = require('passport');

// Import each strategy
require('./strategies/google.strategy')(passport);
require('./strategies/facebook.strategy')(passport); // create later
require('./strategies/github.strategy')(passport);

// Serialize & deserialize
const User = require('../models/user.model');

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

module.exports = passport;
