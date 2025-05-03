const GitHubStrategy = require('passport-github2').Strategy;
const User = require('../../models/user.model');

module.exports = (passport) => {
  const { GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, BASE_URL } = process.env;

  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET || !BASE_URL) {
    console.error('Missing GitHub OAuth environment variables');
    process.exit(1);
  }

  passport.use(
    new GitHubStrategy(
      {
        clientID: GITHUB_CLIENT_ID,
        clientSecret: GITHUB_CLIENT_SECRET,
        callbackURL: `${BASE_URL}/api/auth/github/callback`,
        proxy: process.env.NODE_ENV === 'production',
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          if (!profile || !profile.id) return done(new Error('Invalid GitHub profile'), null);
          const email = profile.emails?.[0]?.value;
          const githubId = profile.id;
          const username = profile.username || email.split('@')[0];
          const profilePicture = profile.photos?.[0]?.value || null;

          let user = await User.findOne({ githubId }) || await User.findOne({ email });

          if (user) {
            user.githubId = githubId;
            user.profilePicture = profilePicture || user.profilePicture;
            user.lastLogin = new Date();
            await user.save();
          } else {
            user = await User.create({
              username,
              email,
              githubId,
              profilePicture,
              isEmailVerified: true,
              isActive: true,
              lastLogin: new Date(),
            });
          }

          return done(null, user);
        } catch (error) {
          console.error(`GitHub Auth Error: ${error.message}`);
          return done(error, null);
        }
      }
    )
  );
};
