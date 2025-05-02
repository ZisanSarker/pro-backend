const jwt = require('jsonwebtoken');

/**
 * Generate JWT access and refresh tokens for a user
 * @param {string} userId - MongoDB user ID
 * @returns {Object} Object containing accessToken and refreshToken
 */
const generateTokens = (userId) => {
  if (!process.env.JWT_ACCESS_SECRET || !process.env.JWT_REFRESH_SECRET) {
    throw new Error('JWT secret keys not defined in environment variables');
  }
  
  const accessToken = jwt.sign(
    { userId }, 
    process.env.JWT_ACCESS_SECRET, 
    { expiresIn: '15m' }
  );
  
  const refreshToken = jwt.sign(
    { userId }, 
    process.env.JWT_REFRESH_SECRET, 
    { expiresIn: '7d' }
  );
  
  return { accessToken, refreshToken };
};

module.exports = generateTokens;