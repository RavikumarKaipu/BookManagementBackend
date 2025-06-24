require('dotenv').config(); 
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const authenticateToken = require('./middleWare/authenticateToken');

const User = require('../models/User');
const Book = require('../models/Book');
const otpStore = new Map();

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY;

app.use(cors());
app.use(express.json());

// Connect MongoDB
mongoose.connect(process.env.MONGO_URI);
mongoose.connection.once('open', ()=>console.log('✅ MongoDB connected'));
mongoose.connection.on('error', err=>console.error('❌ MongoDB error', err));

// Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL, pass: process.env.EMAIL_PASS }
});


app.get('/', (req, res) => res.json({ status: 'OK', time: new Date().toLocaleTimeString() }));

// —– Auth Routes —–

app.post('/api/signup', async (req, res) => {
  const { username, email, password, isAdmin = false } = req.body;

  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields are required' });

  try {
    if (await User.findOne({ $or: [{ username }, { email }] }))
      return res.status(400).json({ error: 'Username or email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    await new User({ username, email, password: hashed }).save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err); res.status(500).json({ error: 'Server error on signup' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

     const token = jwt.sign({ id: user._id, username: user.username,isAdmin: user.isAdmin }, SECRET_KEY, { expiresIn: '1d' });
    res.status(200).json({
        token,
        username:user.username,
        email:user.email,
        isAdmin:user.isAdmin
    })
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// —– OTP / Password Reset —–

app.post('/api/verify-email', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  if (!await User.exists({ email }))
    return res.status(404).json({ error: 'Email not found' });

  res.json({ message: 'Email exists, you may request OTP.' });
});

app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const otp = Math.floor(100000 + Math.random()*900000);
  const timestamp = Date.now();

  try {
    await transporter.sendMail({
      from: process.env.EMAIL, to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP is: ${otp}`
    });
    otpStore.set(email, { otp, timestamp });
    res.json({ message: 'OTP sent successfully' });
  } catch (err) {
    console.error(err); res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  const { email, otp: userOtp } = req.body;
  const stored = otpStore.get(email);

  if (!stored) return res.status(400).json({ error: 'No OTP requested' });
  const ageMins = (Date.now() - stored.timestamp) / 60000;
  if (ageMins > 10) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'OTP expired' });
  }
  if (Number(userOtp) !== stored.otp)
    return res.status(400).json({ error: 'Invalid OTP' });

  otpStore.delete(email);
  res.json({ message: 'OTP verified' });
});

app.post('/api/update-password', async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword)
    return res.status(400).json({ error: 'Missing email or password' });

  const hashed = await bcrypt.hash(newPassword, 10);
  const result = await User.findOneAndUpdate({ email }, { password: hashed });
  if (!result) return res.status(404).json({ error: 'Email not found' });

  res.json({ message: 'Password updated' });
});

// —– User Management —–

app.get('/users', authenticateToken, async (req, res) => {
  const { username, isAdmin } = req.user;

  if (!isAdmin || username !== 'Ravi_9392') {
    return res.status(403).json({ error: 'Access restricted to admin' });
  }

  const users = await User.find({}, 'id username email createdAt');
  res.status(200).json(users);
});

app.delete('/users/:id',authenticateToken,async (req,res)=>{
    if(req.user.username!=='Ravi_9392'){
        return res.status(403).json({error:'Access restricted to admin'})

    }
    const result=await User.findByIdAndDelete(req.params.id);
    if(!result) return res.status(404).json({error:'User Not Found'})
    res.status(204).end()
})

// —– Books CRUD —–


app.get('/books', authenticateToken, async (req, res) => {
  try {
    const books = await Book.find({ userId: req.user.id }); // ← only this user's books
    res.json(books);
  } catch (err) {
    res.status(500).json({ error: 'Error fetching books' });
  }
});


app.post('/books', authenticateToken, async (req, res) => {
  const newBook = new Book({
    ...req.body,
    userId: req.user.id, // ← set from decoded token
  });

  try {
    const savedBook = await newBook.save();
    res.status(201).json(savedBook);
  } catch (err) {
    res.status(500).json({ error: 'Failed to save book' });
  }
});


app.get('/books/:id', authenticateToken, async (req, res) => {
  const book = await Book.findOne({ _id: req.params.id, userId: req.user.id });
  if (!book) return res.status(404).json({ error: 'Not found or unauthorized' });

  res.json(book);
});

app.put('/books/:id', authenticateToken, async (req, res) => {


  const book = await Book.findOneAndUpdate(
    { _id: req.params.id, userId: req.user.id },
    req.body,
    { new: true }
  );
  if (!book) return res.status(404).json({ error: 'Not found or unauthorized' });
  res.json(book);
});

app.delete('/books/:id', authenticateToken, async (req, res) => {
  const book = await Book.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
  if (!book) return res.status(404).json({ error: 'Not found or unauthorized' });
  res.json({ message: 'Deleted successfully' });
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
