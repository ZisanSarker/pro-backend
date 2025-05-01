const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  oauthId: { type: String, unique: true },
  provider: { type: String },
});

userSchema.statics.findOrCreate = async function (oauthId, username, email) {
  let user = await this.findOne({ oauthId });
  if (!user) {
    user = new this({ oauthId, username, email, provider: 'oauth' });
    await user.save();
  }
  return user;
};

module.exports = mongoose.model('User', userSchema);
