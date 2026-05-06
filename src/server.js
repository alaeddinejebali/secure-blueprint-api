import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import morgan from 'morgan';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';

import connectDB from './config/database.js';
import authRoutes from './routes/auth.js';
import deviceRoutes from './routes/devices.js';
import serviceRoutes from './routes/services.js';

dotenv.config();

const app = express();

// ====================== SECURITY MIDDLEWARE ======================

// SECURITY: Helmet sets a collection of protective HTTP response headers:
//   - X-Content-Type-Options: nosniff       → prevents MIME-type sniffing
//   - X-Frame-Options: DENY                 → blocks clickjacking via iframes
//   - Content-Security-Policy               → restricts resource loading (XSS mitigation)
//   - Strict-Transport-Security             → enforces HTTPS
//   - X-XSS-Protection                      → legacy XSS filter for older browsers
// Without this, browsers apply no client-side protections at all.
app.use(helmet());

// SECURITY: Restrict cross-origin requests to a specific trusted origin.
// Using origin: '*' (wildcard) would allow any website to send requests
// to this API on behalf of a logged-in user — a classic CORS misconfiguration.
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// SECURITY: Limit the accepted body size to 10kb.
// Without a limit, an attacker can send enormous payloads to exhaust
// server memory or cause a denial of service (the vulnerable version allowed 100mb).
app.use(express.json({ limit: '10kb' }));

// SECURITY: Strip MongoDB query operators ($gt, $ne, $where, etc.) from
// req.body, req.params, and req.query before they reach any database call.
// Without this, an attacker can inject operators into query fields and
// bypass filters or dump entire collections (NoSQL Injection).
app.use(mongoSanitize());

// SECURITY: Global rate limiter — max 100 requests per 15 minutes per IP.
// Prevents automated scanning, scraping, and general abuse.
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later.' },
});
app.use(globalLimiter);

// SECURITY: Stricter rate limit on auth endpoints — max 10 attempts per 15 minutes.
// Brute-forcing a login endpoint is trivial without this. At 10 req/15min an
// attacker would need years to guess a reasonably strong password.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many authentication attempts, please try again later.' },
});
app.use('/api/auth', authLimiter);

// Logging — 'tiny' format avoids logging request bodies which could contain passwords.
app.use(morgan('tiny'));

// ====================== ROUTES ======================
app.use('/api/auth', authRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/services', serviceRoutes);

app.get('/', (req, res) => {
  res.json({ message: 'Homelab API' });
});

// ====================== GLOBAL ERROR HANDLER ======================
// SECURITY: Catch all unhandled errors and return a generic message.
// Never expose error.message or error.stack to the client — they reveal
// internal structure (model names, file paths, driver versions) useful to attackers.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Internal server error' });
});

// ====================== START SERVER ======================
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  await connectDB();
  app.listen(PORT, () => {
    console.log(`API running on http://localhost:${PORT}`);
  });
};

startServer();
