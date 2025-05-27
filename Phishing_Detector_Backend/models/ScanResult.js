const mongoose = require('mongoose');

const ScanResultSchema = new mongoose.Schema({
  itemType: String,
  value: String, 
  status: String,
  vendors: [String],
  scannedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('ScanResult', ScanResultSchema);
