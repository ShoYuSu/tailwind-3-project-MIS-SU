const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt'); // ⭐️ นำเข้า bcrypt 

const app = express();

// อนุญาตให้ Angular (Port 4200) เข้าถึง API ได้
app.use(cors());
// ให้ API รับ-ส่งข้อมูลแบบ JSON ได้
app.use(express.json());

// ⭐️ ตั้งค่าการเชื่อมต่อฐานข้อมูล XAMPP
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',      // XAMPP ปกติ user คือ root
  password: '',      // XAMPP ปกติ password จะว่างเปล่า
  database: 'scidb'  // ชื่อฐานข้อมูล
});

// ทดสอบเชื่อมต่อฐานข้อมูล
db.connect((err) => {
  if (err) {
    console.error('❌ เชื่อมต่อฐานข้อมูลล้มเหลว:', err);
    return;
  }
  console.log('✅ เชื่อมต่อฐานข้อมูล scidb สำเร็จ!');
});

// ==========================================
// 🚀 สร้างเส้นทาง API (Endpoints)
// ==========================================

// 1. API ทดสอบว่า Server ทำงานไหม
app.get('/api/test', (req, res) => {
  res.json({ message: 'API ทำงานปกติ พร้อมให้บริการ!' });
});

// 2. API ดึงรายชื่อผู้ใช้งาน (Users)
app.get('/api/users', (req, res) => {
  const sql = 'SELECT * FROM users';
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// 3. API ดึงข้อมูลบุคลากร (Staff / Persons)
app.get('/api/staff', (req, res) => {
  const sql = 'SELECT * FROM persons';
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

// 4. API สำหรับเพิ่มบุคลากรใหม่และกำหนดสิทธิ์
app.post('/api/staff', async (req, res) => {
  const { fullName, staffCode, email, department, roleId, permissions } = req.body;

  try {
    const dbPromise = db.promise();

    // 4.1 เข้ารหัสผ่าน (ใช้รหัสประจำตัวเป็นรหัสผ่านเริ่มต้น)
    const hashedPassword = await bcrypt.hash(staffCode, 10);

    // 4.2 บันทึกลงตาราง users (ใช้ email เป็น username)
    const [userResult] = await dbPromise.query(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [email, hashedPassword]
    );
    const userId = userResult.insertId;

    // 4.3 บันทึกลงตาราง persons
    await dbPromise.query(
      'INSERT INTO persons (user_id, full_name, email) VALUES (?, ?, ?)',
      [userId, fullName, email]
    );

    // 4.4 บันทึกลงตาราง user_roles
    await dbPromise.query(
      'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
      [userId, roleId]
    );

    // 4.5 บันทึกลงตาราง permissions (วนลูปตามโมดูลที่ส่งมา)
    for (const p of permissions) {
      await dbPromise.query(
        'INSERT INTO permissions (user_id, module_name, action, scope) VALUES (?, ?, "view", ?)',
        [userId, p.module, p.view]
      );
      
      if (p.module !== 'Dashboard') {
        await dbPromise.query(
          'INSERT INTO permissions (user_id, module_name, action, scope) VALUES (?, ?, "add", ?)',
          [userId, p.module, p.add]
        );
        await dbPromise.query(
          'INSERT INTO permissions (user_id, module_name, action, scope) VALUES (?, ?, "edit", ?)',
          [userId, p.module, p.edit]
        );
        await dbPromise.query(
          'INSERT INTO permissions (user_id, module_name, action, scope) VALUES (?, ?, "delete", ?)',
          [userId, p.module, p.edit]
        );
      }
    }

    res.json({ success: true, message: 'บันทึกข้อมูลบุคลากรและสิทธิ์สำเร็จ!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล' });
  }
});

// 5. 🔓 API สำหรับเข้าสู่ระบบ (เวอร์ชันปรับปรุง: ปล่อยผ่านทุกสิทธิ์เข้า Dashboard ทันที)
app.post('/api/login', async (req, res) => {
  const user_input = req.body.email || req.body.username; 
  const password_input = req.body.password;

  try {
    const dbPromise = db.promise();

    // ดึงข้อมูลแบบ Join ตารางเพื่อเอาข้อมูลไปใช้งานต่อฝั่ง Angular
    const sql = `
      SELECT u.user_id, u.password_hash, r.role_name, p.full_name, sp.student_code 
      FROM users u
      LEFT JOIN persons p ON u.user_id = p.user_id
      LEFT JOIN user_roles ur ON u.user_id = ur.user_id
      LEFT JOIN roles r ON ur.role_id = r.role_id
      LEFT JOIN student_profiles sp ON p.person_id = sp.person_id
      WHERE u.username = ? OR p.email = ? LIMIT 1
    `;

    const [results] = await dbPromise.query(sql, [user_input, user_input]);

    if (results.length > 0) {
      const row = results[0];
      
      // ตรวจสอบรหัสผ่านด้วย bcrypt
      const isMatch = await bcrypt.compare(password_input, row.password_hash);

      if (isMatch) {
        // ✅ ผ่านฉลุย! ส่งข้อมูลกลับไปให้ Angular ดีดเข้าหน้า Dashboard ทันที ไม่บล็อกสิทธิ์แล้ว
        res.json({
          success: true,
          role: row.role_name,
          full_name: row.full_name || "ไม่ระบุชื่อ",
          student_code: row.student_code || "",
          user_id: row.user_id,
          user: {
             userId: row.user_id,
             username: user_input,
             fullName: row.full_name || "ไม่ระบุชื่อ",
             roleName: row.role_name
          }
        });

      } else {
        res.status(401).json({ success: false, message: "รหัสผ่านไม่ถูกต้อง" });
      }
    } else {
      res.status(401).json({ success: false, message: "ไม่พบผู้ใช้งาน" });
    }

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "เกิดข้อผิดพลาดที่เซิร์ฟเวอร์", error: error.message });
  }
});

// 6. 🛠️ API รีเซ็ตรหัสผ่าน admin เป็น 123456
app.get('/api/reset', async (req, res) => {
  try {
    const newHash = await bcrypt.hash('123456', 10); 
    
    db.query(
      'UPDATE users SET password_hash = ? WHERE username = "admin"',
      [newHash],
      (err) => {
        if (err) return res.send('พังจ้า: ' + err.message);
        res.send(`<h1>✅ เปลี่ยนรหัสผ่าน admin เป็น 123456 สำเร็จแล้ว!</h1> <p>กลับไปล็อกอินที่หน้าเว็บได้เลยครับ</p>`);
      }
    );
  } catch (error) {
    res.send('เกิดข้อผิดพลาด');
  }
});

// ==========================================
// เปิด Server ให้ทำงานที่ Port 3000
// ==========================================
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 API Server รันอยู่บน http://localhost:${PORT}`);
});