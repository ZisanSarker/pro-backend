const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../../models/user.model');

module.exports = (passport) => {
  const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, BASE_URL } = process.env;
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !BASE_URL) {
    console.error('Missing Google OAuth environment variables');
    process.exit(1);
  }

  passport.use(
    new GoogleStrategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: `${BASE_URL}/api/auth/google/callback`,
        proxy: process.env.NODE_ENV === 'production',
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          if (!profile || !profile.id) return done(new Error('Invalid Google profile'), null);

          const email = profile.emails?.[0]?.value;
          if (!email) return done(new Error('Email not provided'), null);

          const googleId = profile.id;
          const username = profile.displayName || email.split('@')[0];
          const profilePicture = profile.photos?.[0]?.value || null;

          let user = await User.findOne({ googleId }) || await User.findOne({ email });

          if (user) {
            user.googleId = googleId;
            user.profilePicture = profilePicture || user.profilePicture;
            user.lastLogin = new Date();
            await user.save();
          } else {
            user = await User.create({
              username,
              email,
              googleId,
              profilePicture,
              isEmailVerified: true,
              isActive: true,
              lastLogin: new Date(),
            });
          }

          return done(null, user);
        } catch (error) {
          console.error(`Google Auth Error: ${error.message}`);
          return done(error, null);
        }
      }
    )
  );
};
