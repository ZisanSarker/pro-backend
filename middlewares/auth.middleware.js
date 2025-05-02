const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
  const accessToken = req.cookies.accessToken;
  
  const authHeader = req.headers.authorization;
  const headerToken = authHeader && authHeader.split(' ')[1];
  

  const token = accessToken || headerToken;
  
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        message: 'Token expired',
        expired: true
      });
    }
    
    return res.status(403).json({ message: 'Invalid token' });
  }
};

module.exports = authMiddleware;