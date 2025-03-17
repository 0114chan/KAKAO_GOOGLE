const express = require('express');
const router = express.Router();
const db = require('../config/db');
const authMiddleware = require('../middleware/authMiddleware');

// 관리자 전용 라우트
router.use(authMiddleware('admin'));

// 일반 사용자 목록 조회
router.get('/users', async (req, res) => {
    try {
        const [users] = await db.query('SELECT id, email, role, is_banned FROM users WHERE role = "user"');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users', details: error.message });
    }
});

// 일반 사용자 차단
router.post('/users/:id/ban', async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('UPDATE users SET is_banned = TRUE WHERE id = ? AND role = "user"', [id]);
        res.json({ message: 'User banned successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to ban user', details: error.message });
    }
});

// 일반 사용자 차단 해제
router.post('/users/:id/unban', async (req, res) => {
    const { id } = req.params;
    try {
        await db.query('UPDATE users SET is_banned = FALSE WHERE id = ? AND role = "user"', [id]);
        res.json({ message: 'User unbanned successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to unban user', details: error.message });
    }
});

// 직원/관리자 사원번호 등록
router.post('/employee/register', async (req, res) => {
    const { employeeId, role } = req.body;

    if (!employeeId || !/^[A-Za-z0-9]{10}$/.test(employeeId)) {
        return res.status(400).json({ error: 'Invalid employee ID format (10 characters, alphanumeric)' });
    }
    if (!['company', 'admin'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role (must be "company" or "admin")' });
    }

    try {
        await db.query('INSERT INTO users (role, employee_id) VALUES (?, ?)', [role, employeeId]);
        res.json({ message: 'Employee registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to register employee', details: error.message });
    }
});

module.exports = router;
