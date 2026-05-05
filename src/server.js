import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import morgan from 'morgan';

import connectDB from './config/database.js';
import authRoutes from './routes/auth.js';
import deviceRoutes from './routes/devices.js';
import serviceRoutes from './routes/services.js';

dotenv.config();

const app = express();

// === HIGHLY VULNERABLE CONFIGURATION ===
app.use(cors({ origin: '*' }));             // Allows any origin
app.use(express.json({ limit: '100mb' }));  // No size limit
app.use(morgan('dev'));                     // Very detailed logging

// No Helmet, No rate limiting, No mongo sanitize, No security middleware

// ====================== ROUTES ======================
app.use('/api/auth', authRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/services', serviceRoutes);

app.get('/', (req, res) => {
  res.json({ 
    message: '🚨 VULNERABLE Homelab API',
    warning: 'This version is INTENTIONALLY insecure - For educational purposes only'
  });
});

// ====================== START SERVER ======================
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  try {
    await connectDB();
    
    app.listen(PORT, () => {
      console.log(`VULNERABLE API running on http://localhost:${PORT}`);
      console.log(`This version contains multiple intentional security flaws for learning`);
    });

  } catch (error) {
    console.error('Failed to start server:', error.message);
    // In vulnerable version: we still try to start the server even if DB fails
    console.log('Starting server anyway without database...');
    
    app.listen(PORT, () => {
      console.log(`VULNERABLE API running on http://localhost:${PORT} (without DB)`);
    });
  }
};

startServer();