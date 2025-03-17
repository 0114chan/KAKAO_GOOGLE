const jwt = require('jsonwebtoken');

module.exports = (requiredRole = null) => (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token' });

        req.user = decoded;
        if (requiredRole && decoded.role !== requiredRole) {
            return res.status(403).json({ error: 'Access denied: insufficient permissions' });
        }
        if (decoded.is_banned) {
            return res.status(403).json({ error: 'Account is banned' });
        }
        next();
    });
};
