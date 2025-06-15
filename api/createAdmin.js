// createAdmin.js
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User'); // Adjust path to your User model

const createAdmin = async () => {
  await mongoose.connect(process.env.MONGO_URI); // or your DB URI directly

  const existingAdmin = await User.findOne({ username: 'Ravi_9392' });
  if (existingAdmin) {
    console.log('Admin already exists.');
    process.exit();
  }

  const hashedPassword = await bcrypt.hash('Ravi@8341', 10);

  const adminUser = new User({
    username: 'Ravi_9392',
    password: hashedPassword,
    email: 'ravi@example.com',
    isAdmin: true,
  });

  await adminUser.save();
  console.log('✅ Admin user created!');
  process.exit();
};

createAdmin();
