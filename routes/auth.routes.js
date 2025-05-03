const express = require('express');
const controller = require('../controllers/auth.controller');
const authMiddleware = require('../middlewares/auth.middleware');
const router = express.Router();

// ──────── Local Auth Routes ────────

// Public routes
router.post('/register', controller.register);
router.post('/login', controller.login);
router.post('/refresh-token', controller.refreshToken);

// Protected routes
router.get('/logout', authMiddleware, controller.logout);
router.get('/me', authMiddleware, controller.getCurrentUser);

// ──────── OAuth Routes ────────
router.get('/google', controller.startGoogleAuth);
router.get('/google/callback', controller.handleGoogleCallback);

router.get('/github', controller.startGithubAuth);
router.get('/github/callback', controller.handleGithubCallback);

router.get('/facebook', controller.startFacebookAuth);
router.get('/facebook/callback', controller.handleFacebookCallback);

module.exports = router;
