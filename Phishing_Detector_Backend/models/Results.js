const mongoose = require('mongoose');

const resultSchema = new mongoose.Schema({
  item_type: String,
  value: String,
  status: String,
  vendors: [String],
  scanned_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Result', resultSchema);
