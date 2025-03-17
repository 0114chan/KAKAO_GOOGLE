const express = require('express');
const router = express.Router();
const axios = require('axios');
const jwt = require('jsonwebtoken');
const db = require('../config/db');

const logger = {
    info: (provider, message, data = {}) => console.log(`[${provider.toUpperCase()} AUTH] [INFO] ${message}`, JSON.stringify(data)),
    error: (provider, message, error) => console.error(`[${provider.toUpperCase()} AUTH] [ERROR] ${message}`, error.response?.data || error.message),
    debug: (provider, message, data = {}) => console.log(`[${provider.toUpperCase()} AUTH] [DEBUG] ${message}`, JSON.stringify(data)),
};

let processedCodes = new Set();
const isCodeProcessed = (code) => {
    if (processedCodes.has(code)) return true;
    processedCodes.add(code);
    if (processedCodes.size > 100) processedCodes.delete(processedCodes.values().next().value);
    return false;
};

const handleOAuthCallback = async (provider, code, tokenUrl, userInfoUrl, clientId, redirectUri, clientSecret = null) => {
    if (!code) throw new Error('No code provided');
    if (isCodeProcessed(code)) throw new Error('Duplicate code detected');

    logger.info(provider, 'Starting token request', { code: code.substring(0, 10) + '...' });
    const params = clientSecret
        ? { code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: 'authorization_code' }
        : { grant_type: 'authorization_code', client_id: clientId, redirect_uri: redirectUri, code };

    const tokenResponse = await axios.post(tokenUrl, clientSecret ? params : null, { params: clientSecret ? null : params });
    logger.debug(provider, 'Token received', { access_token: tokenResponse.data.access_token.substring(0, 10) + '...' });

    logger.info(provider, 'Starting user info request');
    const userResponse = await axios.get(userInfoUrl, { headers: { Authorization: `Bearer ${tokenResponse.data.access_token}` } });
    logger.debug(provider, 'User info retrieved', { userData: userResponse.data });

    return userResponse.data;
};

router.post('/kakao/callback', async (req, res) => {
    const provider = 'kakao';
    try {
        const { code } = req.body;
        logger.info(provider, 'Received auth code', { code: code?.substring(0, 10) + '...' });

        const userData = await handleOAuthCallback(
            provider,
            code,
            'https://kauth.kakao.com/oauth/token',
            'https://kapi.kakao.com/v2/user/me',
            process.env.KAKAO_CLIENT_ID,
            process.env.KAKAO_REDIRECT_URI
        );

        const { id, kakao_account, properties } = userData;
        const email = kakao_account?.email || properties?.email || `${id}@kakao.com`;
        logger.debug(provider, 'Processed user data', { email, provider_id: id });

        const [results] = await db.query(
            'INSERT INTO users (email, provider, provider_id, role) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE id=id',
            [email, provider, id, 'user']
        );
        const userId = results.insertId || (await db.query('SELECT id FROM users WHERE email = ?', [email]))[0][0].id;
        const [user] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
        logger.info(provider, 'User upserted', { userId, isNewUser: results.insertId > 0 });

        const token = jwt.sign({ id: userId, role: 'user', is_banned: user[0].is_banned }, process.env.JWT_SECRET, { expiresIn: '1h' });
        logger.info(provider, 'JWT generated', { token: token.substring(0, 20) + '...' });
        res.json({ token, role: 'user', isNewUser: results.insertId > 0 });
    } catch (error) {
        logger.error(provider, 'Authentication failed', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

router.post('/google/callback', async (req, res) => {
    const provider = 'google';
    try {
        const { code } = req.body;
        logger.info(provider, 'Received auth code', { code: code?.substring(0, 10) + '...' });

        const userData = await handleOAuthCallback(
            provider,
            code,
            'https://oauth2.googleapis.com/token',
            'https://www.googleapis.com/oauth2/v2/userinfo',
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_REDIRECT_URI,
            process.env.GOOGLE_CLIENT_SECRET
        );

        const { email, id } = userData;
        logger.debug(provider, 'Processed user data', { email, provider_id: id });

        const [results] = await db.query(
            'INSERT INTO users (email, provider, provider_id, role) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE id=id',
            [email, provider, id, 'user']
        );
        const userId = results.insertId || (await db.query('SELECT id FROM users WHERE email = ?', [email]))[0][0].id;
        const [user] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);
        logger.info(provider, 'User upserted', { userId, isNewUser: results.insertId > 0 });

        const token = jwt.sign({ id: userId, role: 'user', is_banned: user[0].is_banned }, process.env.JWT_SECRET, { expiresIn: '1h' });
        logger.info(provider, 'JWT generated', { token: token.substring(0, 20) + '...' });
        res.json({ token, role: 'user', isNewUser: results.insertId > 0 });
    } catch (error) {
        logger.error(provider, 'Authentication failed', error);
        res.status(500).json({ error: 'Authentication failed' });
    }
});

router.post('/employee/login', async (req, res) => {
    const { employeeId } = req.body;
    logger.info('employee', 'Received login attempt', { employeeId });

    if (!employeeId || !/^[A-Za-z0-9]{10}$/.test(employeeId)) {
        logger.error('employee', 'Invalid employee ID format');
        return res.status(400).json({ error: 'Invalid employee ID format (10 characters, alphanumeric)' });
    }

    try {
        const [users] = await db.query('SELECT * FROM users WHERE employee_id = ?', [employeeId]);
        if (users.length === 0) {
            logger.error('employee', 'Employee ID not found');
            return res.status(404).json({ error: 'Employee ID not found' });
        }

        const user = users[0];
        const token = jwt.sign({ id: user.id, role: user.role, is_banned: user.is_banned }, process.env.JWT_SECRET, { expiresIn: '1h' });
        logger.info('employee', 'Login successful', { userId: user.id, role: user.role });
        res.json({ token, role: user.role });
    } catch (error) {
        logger.error('employee', 'Login failed', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

module.exports = router;
