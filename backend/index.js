const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = 4000;
const SECRET_KEY = 'your_secret_key';

app.use(cors());
app.use(bodyParser.json());

// Initialize SQLite database
const db = new sqlite3.Database(':memory:');

// Create tables
const createTables = () => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT,
    likes INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
};

createTables();

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Register user
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
  stmt.run(username, hashedPassword, function (err) {
    if (err) {
      return res.status(400).json({ message: 'Username already exists' });
    }
    res.status(201).json({ message: 'User registered successfully' });
  });
  stmt.finalize();
});

// Login user
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).json({ message: 'Internal server error' });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY);
    res.json({ token });
  });
});

// Create a post
app.post('/api/posts', authenticateToken, (req, res) => {
  const { content } = req.body;
  if (!content) {
    return res.status(400).json({ message: 'Content is required' });
  }
  const stmt = db.prepare('INSERT INTO posts (user_id, content) VALUES (?, ?)');
  stmt.run(req.user.id, content, function (err) {
    if (err) return res.status(500).json({ message: 'Internal server error' });
    res.status(201).json({ id: this.lastID, content, likes: 0 });
  });
  stmt.finalize();
});

// Get all posts
app.get('/api/posts', (req, res) => {
  db.all(
    `SELECT posts.id, posts.content, posts.likes, posts.created_at, users.username
     FROM posts JOIN users ON posts.user_id = users.id
     ORDER BY posts.created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ message: 'Internal server error' });
      res.json(rows);
    }
  );
});

// Like a post
app.post('/api/posts/:id/like', authenticateToken, (req, res) => {
  const postId = req.params.id;
  db.run('UPDATE posts SET likes = likes + 1 WHERE id = ?', [postId], function (err) {
    if (err) return res.status(500).json({ message: 'Internal server error' });
    if (this.changes === 0) return res.status(404).json({ message: 'Post not found' });
    res.json({ message: 'Post liked' });
  });
});

// Get posts by user
app.get('/api/users/:username/posts', (req, res) => {
  const username = req.params.username;
  db.all(
    `SELECT posts.id, posts.content, posts.likes, posts.created_at
     FROM posts JOIN users ON posts.user_id = users.id
     WHERE users.username = ?
     ORDER BY posts.created_at DESC`,
    [username],
    (err, rows) => {
      if (err) return res.status(500).json({ message: 'Internal server error' });
      res.json(rows);
    }
  );
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
