// config/passport.js
require('dotenv').config();
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/user.model');

/**
 * Configure Passport.js Google OAuth strategy
 */
const configurePassport = () => {
  // Validate required environment variables
  const requiredEnvVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'BASE_URL'];
  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length) {
    console.error(`Missing required environment variables: ${missingVars.join(', ')}`.red.bold);
    process.exit(1);
  }

  passport.use(
    new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/api/auth/google/callback`,
      // Add proxy support for production environments behind reverse proxy
      proxy: process.env.NODE_ENV === 'production'
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Validate required profile data
        if (!profile || !profile.id) {
          return done(new Error('Invalid profile data received from Google'), null);
        }
        
        const email = profile.emails?.[0]?.value;
        if (!email) {
          return done(new Error('Email not provided by Google OAuth'), null);
        }
        
        const oauthId = profile.id;
        const username = profile.displayName || email.split('@')[0];
        const profilePicture = profile.photos?.[0]?.value || null;
        
        // Find existing user by oauthId first (primary match)
        let user = await User.findOne({ oauthId });
        
        // If no user found by oauthId, try finding by email
        if (!user) {
          user = await User.findOne({ email });
          
          if (user) {
            // Update existing user with Google data if not already linked
            user.oauthId = oauthId;
            if (profilePicture) {
              user.profilePicture = profilePicture;
            }
            await user.save();
          } else {
            // Create new user if not found
            user = await User.create({
              username,
              email,
              oauthId,
              profilePicture,
              isEmailVerified: true,
              isActive: true,
              lastLogin: new Date()
            });
          }
        } else {
          // Update last login time
          user.lastLogin = new Date();
          await user.save();
        }
        
        return done(null, user);
      } catch (error) {
        console.error(`Google Auth Error: ${error.message}`);
        done(error, null);
      }
    })
  );

  // Configure session serialization
  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      if (!user) {
        return done(new Error('User not found'), null);
      }
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  });

  return passport;
};

module.exports = configurePassport();