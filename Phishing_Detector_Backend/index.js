require('dotenv').config();
const express = require('express');
const axios = require('axios');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const Result = mongoose.model('Result', new mongoose.Schema({
  type: String,
  value: String,
  status: String,
  vendors: [String],
  scannedAt: { type: Date, default: Date.now }
}));

const VT_API_KEY = process.env.VT_API_KEY;

// --- Helper Function ---
const parseResult = (data) => {
  try {
    const analysis = data.data.attributes.last_analysis_results;
    const malicious = Object.entries(analysis).filter(([_, result]) =>
      result.category === 'malicious' || result.category === 'phishing'
    );
    return {
      status: malicious.length > 0 ? 'Malicious' : 'Safe',
      vendors: malicious.map(([vendor]) => vendor)
    };
  } catch {
    return { status: 'Unknown', vendors: [] };
  }
};

// --- URL Scan ---
app.post('/scan/url', async (req, res) => {
  const { url } = req.body;
  try {
    const scanRes = await axios.post('https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url }),
      { headers: { 'x-apikey': VT_API_KEY } });

    const id = scanRes.data.data.id;
    const report = await axios.get(`https://www.virustotal.com/api/v3/analyses/${id}`,
      { headers: { 'x-apikey': VT_API_KEY } });

    const parsed = parseResult(report.data);
    await Result.create({ type: 'url', value: url, ...parsed });
    res.json(parsed);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to scan URL' });
  }
});

// --- Email Scan ---
app.post('/scan/email', async (req, res) => {
  const { content } = req.body;
  try {
    const buffer = Buffer.from(content, 'utf-8');
    const tempPath = path.join(__dirname, 'email.txt');
    fs.writeFileSync(tempPath, buffer);

    const form = new FormData();
    form.append('file', fs.createReadStream(tempPath));

    const scanRes = await axios.post('https://www.virustotal.com/api/v3/files',
      form, { headers: { 'x-apikey': VT_API_KEY, ...form.getHeaders() } });

    const fileID = scanRes.data.data.id;
    const report = await axios.get(`https://www.virustotal.com/api/v3/analyses/${fileID}`,
      { headers: { 'x-apikey': VT_API_KEY } });

    fs.unlinkSync(tempPath);
    const parsed = parseResult(report.data);
    await Result.create({ type: 'email', value: content, ...parsed });
    res.json(parsed);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to scan email' });
  }
});

// --- Document Scan ---
const upload = multer({ dest: 'uploads/' });
app.post('/scan/file', upload.single('file'), async (req, res) => {
  try {
    const form = new FormData();
    form.append('file', fs.createReadStream(req.file.path));

    const scanRes = await axios.post('https://www.virustotal.com/api/v3/files',
      form, { headers: { 'x-apikey': VT_API_KEY, ...form.getHeaders() } });

    const fileID = scanRes.data.data.id;
    const report = await axios.get(`https://www.virustotal.com/api/v3/analyses/${fileID}`,
      { headers: { 'x-apikey': VT_API_KEY } });

    fs.unlinkSync(req.file.path);
    const parsed = parseResult(report.data);
    await Result.create({ type: 'document', value: req.file.originalname, ...parsed });
    res.json(parsed);
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to scan file' });
  }
});

app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));
