const mysql = require('mysql2/promise'); // Promise 기반 모듈 사용
require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true, // 연결 대기 설정
    connectionLimit: 10,      // 최대 연결 수
    queueLimit: 0             // 대기열 제한 없음
});

// 풀을 내보냄 (connect 호출 불필요)
module.exports = pool;
