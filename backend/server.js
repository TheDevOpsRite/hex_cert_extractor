const express = require('express');
const multer = require('multer');
// Install with: npm install cors multer
const cors = require('cors');
const path = require('path');

const app = express();

// Enable CORS for all routes (configure origin as needed)
app.use(cors()); // or: app.use(cors({ origin: 'http://localhost:3000' }));

// Serve frontend static files so images/videos in frontend/ are available over HTTP
// frontend folder: c:\Users\Shivam\Desktop\.sa .sav decryptor\frontend
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// Optional: ensure root serves index.html (useful if directory listing not enabled)
app.get('/', (req, res) => {
	return res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// Use memory storage and allow larger uploads (adjust limit as needed)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 } // 100 MB
});

app.post('/extract-cert', upload.single('apk'), (req, res) => {
  // Validate upload
  if (!req.file) {
    console.error('No file received in request');
    return res.status(400).json({ error: 'No APK file uploaded' });
  }

  console.log(`Received upload: ${req.file.originalname} (${req.file.size} bytes)`);

  // ...existing code to handle uploaded APK (use req.file.buffer)...
  // Return a real response after processing; below is a placeholder example:
  res.json({
    cert_name: req.file.originalname + ".cer",
    cert_len: req.file.size,
    md5_hex: "...",
    sha1_hex: "...",
    sha256_hex: "...",
    first16_hex: "...",
    full_cert_hex_preview: "..."
  });
});

// Multer error handler
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error('Multer error:', err);
    return res.status(400).json({ error: err.message });
  }
  next(err);
});

app.listen(5000, () => console.log('Server listening on 5000'));