const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const cors = require('cors');
app.use(cors());

const databasePath = path.join(__dirname, 'schoolManagement.db');
let database = null;

const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    });
    await createTables();
    app.listen(3000, () => {
      console.log('Server Running at http://localhost:3000/');
    });
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

const createTables = async () => {
  await database.exec(`
    CREATE TABLE IF NOT EXISTS Users (
      user_id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT
    );

    CREATE TABLE IF NOT EXISTS Students (
      student_id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      grade TEXT,
      user_id INTEGER,
      FOREIGN KEY (user_id) REFERENCES Users(user_id)
    );

    CREATE TABLE IF NOT EXISTS Teachers (
      teacher_id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      subject TEXT,
      user_id INTEGER,
      FOREIGN KEY (user_id) REFERENCES Users(user_id)
    );
  `);
};

initializeDbAndServer();

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, 'SECRET_KEY', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Role-based Authorization Middleware
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).send('Access Denied');
    }
    next();
  };
};

// Registration API
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const result = await database.run(
      'INSERT INTO Users (username, password, role) VALUES (?, ?, ?)',
      [username, hashedPassword, role]
    );
    res.status(201).send({ user_id: result.lastID });
  } catch (error) {
    res.status(400).send('User already exists or invalid input');
  }
});

// Login API
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await database.get('SELECT * FROM Users WHERE username = ?', [username]);
  if (user && (await bcrypt.compare(password, user.password))) {
    const token = jwt.sign({ user_id: user.user_id, role: user.role }, 'SECRET_KEY');
    res.json({ token });
  } else {
    res.status(400).send('Invalid Credentials');
  }
});

// Add a Student
app.post('/students', authenticateToken, authorizeRole(['teacher']), async (req, res) => {
  const { name, grade, user_id } = req.body;
  const student = await database.run(
    'INSERT INTO Students (name, grade, user_id) VALUES (?, ?, ?)',
    [name, grade, user_id]
  );
  res.json({ student_id: student.lastID });
});

// Get All Students
app.get('/students', authenticateToken, async (req, res) => {
  const students = await database.all('SELECT * FROM Students');
  res.json(students);
});

// Delete a Student
app.delete('/students/:student_id', authenticateToken, authorizeRole(['teacher']), async (req, res) => {
  const { student_id } = req.params;
  try {
    await database.run('DELETE FROM Students WHERE student_id = ?', [student_id]);
    res.status(200).send('Student deleted successfully');
  } catch (error) {
    res.status(500).send('Error deleting student');
  }
});

// Add a Teacher
app.post('/teachers', authenticateToken, authorizeRole(['teacher']), async (req, res) => {
  const { name, subject, user_id } = req.body;
  const teacher = await database.run(
    'INSERT INTO Teachers (name, subject, user_id) VALUES (?, ?, ?)',
    [name, subject, user_id]
  );
  res.json({ teacher_id: teacher.lastID });
});

// Get All Teachers
app.get('/teachers', authenticateToken, authorizeRole(['teacher']), async (req, res) => {
  const teachers = await database.all('SELECT * FROM Teachers');
  res.json(teachers);
});

// Delete a Teacher
app.delete('/teachers/:teacher_id', authenticateToken, authorizeRole(['teacher']), async (req, res) => {
  const { teacher_id } = req.params;
  try {
    await database.run('DELETE FROM Teachers WHERE teacher_id = ?', [teacher_id]);
    res.status(200).send('Teacher deleted successfully');
  } catch (error) {
    res.status(500).send('Error deleting teacher');
  }
});
