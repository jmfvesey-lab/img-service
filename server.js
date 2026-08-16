const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const AUTH_CODE = process.env.AUTH_CODE || '12345';

// Handle CORS - only allow from own host & throne
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin) return next();

  const isThrone = origin === 'https://throne.com' || /^https:\/\/[\w-]+\.throne\.com$/.test(origin);
  const isSameHost = (() => {
    try { return new URL(origin).host === req.headers.host; } catch { return false; }
  })();

  if (isThrone || isSameHost) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    return next();
  }

  return res.status(403).json({ error: 'Origin not allowed' });
});
app.use(express.json());

// Handle auth
const requireAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const authCode = authHeader ? authHeader.replace('Bearer ', '') : '';

  if (authCode !== AUTH_CODE) {
    if (req.accepts('html')) {
      return res.status(403).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f0f; color: #e4e4e7; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .message { text-align: center; }
    h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 8px; }
    p { color: #71717a; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="message">
    <h1>Access Denied</h1>
    <p>Valid authorization is required to view this page.</p>
  </div>
</body>
</html>`);
    }
    return res.status(403).json({ error: 'Unauthorized: Invalid or missing authentication' });
  }
  next();
};

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    cb(null, crypto.randomUUID() + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'video/mp4', 'video/webm', 'video/quicktime'
    ];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Get all images
app.get('/api/images', requireAuth, (req, res) => {
  fs.readdir(uploadsDir, (err, files) => {
    if (err) return res.status(500).json({ error: 'Failed to read images' });

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const images = files.filter(f =>
      /\.(jpg|jpeg|png|gif|webp)$/i.test(f)
    ).map(f => ({
      filename: f,
      url: `${baseUrl}/uploads/${f}`
    }));

    res.json(images);
  });
});

// Get random image
app.get('/api/random-image', (req, res) => {
  fs.readdir(uploadsDir, (err, files) => {
    if (err) return res.status(500).json({ error: 'Failed to read images' });

    const images = files.filter(f =>
      /\.(jpg|jpeg|png|gif|webp)$/i.test(f)
    );

    if (images.length === 0) {
      return res.status(404).json({ error: 'No images found' });
    }

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const randomImage = images[Math.floor(Math.random() * images.length)];
    res.json({ url: `${baseUrl}/uploads/${randomImage}` });
  });
});

// Get all videos
app.get('/api/videos', requireAuth, (req, res) => {
  fs.readdir(uploadsDir, (err, files) => {
    if (err) return res.status(500).json({ error: 'Failed to read videos' });

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const videos = files.filter(f =>
      /\.(mp4|webm|mov)$/i.test(f)
    ).map(f => ({
      filename: f,
      url: `${baseUrl}/uploads/${f}`
    }));

    res.json(videos);
  });
});

// Get random video
app.get('/api/random-video', (req, res) => {
  fs.readdir(uploadsDir, (err, files) => {
    if (err) return res.status(500).json({ error: 'Failed to read videos' });

    const videos = files.filter(f =>
      /\.(mp4|webm|mov)$/i.test(f)
    );

    if (videos.length === 0) {
      return res.status(404).json({ error: 'No videos found' });
    }

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const randomVideo = videos[Math.floor(Math.random() * videos.length)];
    res.json({ url: `${baseUrl}/uploads/${randomVideo}` });
  });
});

// Upload file (image or video)
app.post('/api/upload', requireAuth, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json({
      success: true,
      filename: req.file.filename,
      url: `${baseUrl}/uploads/${req.file.filename}`
    });
  });
});

// Delete image
app.delete('/api/delete/:filename', requireAuth, (req, res) => {
  const filename = req.params.filename;
  const filePath = path.resolve(uploadsDir, filename);

  // Prevent directory traversal
  if (!filePath.startsWith(uploadsDir + path.sep)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  fs.unlink(filePath, (err) => {
    if (err) return res.status(500).json({ error: 'Failed to delete image' });
    res.json({ success: true });
  });
});

// Serve uploaded images
app.use('/uploads', express.static(uploadsDir));

// Serve admin panel (requires auth)
app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.listen(PORT, () => {
  console.log(`Media service running on port ${PORT}`);
});
