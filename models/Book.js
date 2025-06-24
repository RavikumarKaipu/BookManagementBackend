const mongoose = require('mongoose');

const bookSchema = new mongoose.Schema({
  Title: String,
  Author: String,
  Genre: String,
  Pages: Number,
  PublishedDate: String,
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  }
});

module.exports = mongoose.model('Book', bookSchema);
