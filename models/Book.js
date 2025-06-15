const mongoose = require('mongoose');

const bookSchema = new mongoose.Schema({
  Title: String,
  Author: String,
  Genre: String,
  Pages: Number,
  PublishedDate: String,
});

module.exports = mongoose.model('Book', bookSchema);