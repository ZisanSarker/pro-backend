// config/db.js
const mongoose = require('mongoose');
require('colors');

const connectDB = async () => {
  try {
    const mongoUri = process.env.MONGO_URI;
    
    if (!mongoUri) {
      console.error('MongoDB connection string not found in environment variables'.red.bold);
      process.exit(1);
    }

    // Connection options for reliability and performance
    const options = {
      serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
      heartbeatFrequencyMS: 10000,    // Check server status every 10s
    };

    const conn = await mongoose.connect(mongoUri, options);
    
    // Set up connection event listeners
    mongoose.connection.on('error', err => {
      console.error(`MongoDB connection error: ${err.message}`.red.bold);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.warn('MongoDB disconnected, attempting to reconnect...'.yellow);
    });
    
    console.log(`MongoDB Connected: ${conn.connection.host}`.cyan.bold);
    return conn.connection;
  } catch (err) {
    console.error(`MongoDB Connection Error: ${err.message}`.red.bold);
    process.exit(1);
  }
};

module.exports = connectDB;