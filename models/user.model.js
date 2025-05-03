const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
    trim: true,
    minlength: [3, 'Username must be at least 3 characters'],
    maxlength: [50, 'Username cannot exceed 50 characters'],
  },
  email: {
    type: String,
    required: function () {
      return !this.githubId && !this.facebookId;
    },
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function (val) {
        if (!val && this.githubId && this.facebookId) return true; // allow empty if GitHub login
        return validator.isEmail(val);
      },
      message: 'Please provide a valid email',
    },
  },
  password: {
    type: String,
    required: function () {
      return !this.googleId && !this.githubId && !this.facebookId;
    },
    minlength: [8, 'Password must be at least 8 characters'],
    select: false,
  },

  googleId: {
    type: String,
    unique: true,
    sparse: true,
  },
  githubId: {
    type: String,
    unique: true,
    sparse: true,
  },
  facebookId: {
    type: String,
    unique: true,
    sparse: true,
  },
  profilePicture: {
    type: String,
    default: 'default.jpg',
  },

  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },

  isActive: {
    type: Boolean,
    default: true,
  },

  isEmailVerified: {
    type: Boolean,
    default: false,
  },

  lastLogin: {
    type: Date,
    default: null,
  },

  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

// 🔍 Index on username for efficient querying
userSchema.index({ username: 1 });

/**
 * VIRTUAL: Auth provider
 * Determines whether the user signed up via local, Google, or GitHub
 */
userSchema.virtual('provider').get(function () {
  if (this.googleId) return 'google';
  if (this.githubId) return 'github';
  if (this.facebookId) return 'facebook';
  return 'local';
});

/**
 * Pre-save hook: hash password if modified
 */
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  try {
    this.password = await bcrypt.hash(this.password, 12);

    if (!this.isNew) {
      this.passwordChangedAt = Date.now() - 1000;
    }

    next();
  } catch (err) {
    next(err);
  }
});

/**
 * Instance method: compare passwords
 */
userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

/**
 * Instance method: check if password was changed after token was issued
 */
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }

  return false;
};

/**
 * Instance method: sanitize user object before sending to client
 */
userSchema.methods.toJSON = function () {
  const user = this.toObject();
  delete user.password;
  delete user.passwordChangedAt;
  delete user.passwordResetToken;
  delete user.passwordResetExpires;
  delete user.__v;
  return user;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
