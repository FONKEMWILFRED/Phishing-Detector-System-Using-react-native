// controllers/scanController.js
const axios = require('axios');
const FormData = require('form-data');
const ScanResult = require('../models/ScanResult'); // MongoDB model
const apiKey = process.env.VIRUSTOTAL_API_KEY;

const classifyResult = (data) => {
  if (data?.data?.attributes?.last_analysis_stats?.malicious > 0) {
    return 'Malicious';
  }
  return 'Safe';
};

exports.scanURL = async (req, res) => {
  const { url } = req.body;
  try {
    const response = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      `url=${url}`,
      { headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const scanId = response.data.data.id;

    const result = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${scanId}`,
      { headers: { 'x-apikey': apiKey } }
    );

    const status = classifyResult(result.data);
    const vendors = Object.keys(result.data.data.attributes.results || {}).filter(vendor =>
      result.data.data.attributes.results[vendor].category === 'malicious'
    );

    await ScanResult.create({ type: 'url', input: url, status, vendors });
    res.json({ status, vendors });
  } catch (error) {
    console.error('URL scan failed:', error.message);
    res.status(500).json({ status: 'Error', message: 'Failed to scan URL.' });
  }
};

exports.scanEmail = async (req, res) => {
  const { content } = req.body;
  try {
    const base64 = Buffer.from(content).toString('base64');
    const formData = new FormData();
    formData.append('file', Buffer.from(content), { filename: 'email.txt' });

    const response = await axios.post(
      'https://www.virustotal.com/api/v3/files',
      formData,
      { headers: { 'x-apikey': apiKey, ...formData.getHeaders() } }
    );

    const scanId = response.data.data.id;
    const result = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${scanId}`,
      { headers: { 'x-apikey': apiKey } }
    );

    const status = classifyResult(result.data);
    const vendors = Object.keys(result.data.data.attributes.results || {}).filter(vendor =>
      result.data.data.attributes.results[vendor].category === 'malicious'
    );

    await ScanResult.create({ type: 'email', input: content, status, vendors });
    res.json({ status, vendors });
  } catch (error) {
    console.error('Email scan failed:', error.message);
    res.status(500).json({ status: 'Error', message: 'Failed to scan email.' });
  }
};

exports.scanFile = async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ status: 'Error', message: 'No file uploaded' });

    const formData = new FormData();
    formData.append('file', file.buffer, file.originalname);

    const response = await axios.post(
      'https://www.virustotal.com/api/v3/files',
      formData,
      { headers: { 'x-apikey': apiKey, ...formData.getHeaders() } }
    );

    const scanId = response.data.data.id;
    const result = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${scanId}`,
      { headers: { 'x-apikey': apiKey } }
    );

    const status = classifyResult(result.data);
    const vendors = Object.keys(result.data.data.attributes.results || {}).filter(vendor =>
      result.data.data.attributes.results[vendor].category === 'malicious'
    );

    await ScanResult.create({ type: 'document', input: file.originalname, status, vendors });
    res.json({ status, vendors });
  } catch (error) {
    console.error('File scan failed:', error.message);
    res.status(500).json({ status: 'Error', message: 'Failed to scan file.' });
  }
};
