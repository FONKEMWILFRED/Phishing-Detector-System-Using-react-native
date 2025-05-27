
const express = require('express');
const multer = require('multer');
const router = express.Router();
const scanController = require('../controllers/scanController');

const upload = multer(); // for file uploads

router.post('/url', scanController.scanURL);
router.post('/email', scanController.scanEmail);
router.post('/file', upload.single('file'), scanController.scanFile);

module.exports = router;
