const FacebookStrategy = require('passport-facebook').Strategy;
const User = require('../../models/user.model');

module.exports = (passport) => {
  const {
    FACEBOOK_CLIENT_ID,
    FACEBOOK_CLIENT_SECRET,
    BASE_URL,
    NODE_ENV
  } = process.env;

  if (!FACEBOOK_CLIENT_ID || !FACEBOOK_CLIENT_SECRET || !BASE_URL) {
    console.error('Missing Facebook OAuth environment variables');
    process.exit(1);
  }

  passport.use(
    new FacebookStrategy(
      {
        clientID: FACEBOOK_CLIENT_ID,
        clientSecret: FACEBOOK_CLIENT_SECRET,
        callbackURL: `${BASE_URL}/api/auth/facebook/callback`,
        profileFields: ['id', 'displayName', 'emails', 'photos'],
        enableProof: true,
        proxy: NODE_ENV === 'production',
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          if (!profile || !profile.id) {
            return done(new Error('Invalid Facebook profile'), null);
          }
          console.log(profile);
          const email = profile.emails?.[0]?.value;
          const facebookId = profile.id;
          const username = profile.displayName || email?.split('@')[0] || `fb_user_${facebookId}`;
          const profilePicture = profile.photos?.[0]?.value || null;

          let user = await User.findOne({ facebookId }) || (email && await User.findOne({ email }));

          if (user) {
            user.facebookId = facebookId;
            user.profilePicture = profilePicture || user.profilePicture;
            user.lastLogin = new Date();
            await user.save();
          } else {
            user = await User.create({
              username,
              email,
              facebookId,
              profilePicture,
              isEmailVerified: !!email,
              isActive: true,
              lastLogin: new Date(),
            });
          }

          return done(null, user);
        } catch (error) {
          console.error(`Facebook Auth Error: ${error.message}`);
          return done(error, null);
        }
      }
    )
  );
};
