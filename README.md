# Secure Blueprint API

A cybersecurity home lab project: a Node.js/Express REST API for managing devices, services, and security findings in a cybersecurity homelab, built to demonstrate production-grade security practices in a real codebase.


## ⚠️ IMPORTANT ⚠️

> This repository includes an **intentionally vulnerable branch** (checkout `vulnerable` branch)
> 
> - Start by exploring the [`vulnerable branch`](https://github.com/alaeddinejebali/secure-blueprint-api/tree/vulnerable) to understand the security weaknesses
> 
> - Then, examine the `main` branch to understand how those vulnerabilities are mitigated.
> 
> ✅ Use this comparison to strengthen your understanding of API security best practices.


---

## How to Run

```bash
# 1. Copy the environment file and fill in your own values
cp .env.example .env

# 2. Generate a strong JWT secret (copy the output into .env)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# 3. Start the containers
docker-compose up --build
```

The API will be available at `http://localhost:5000`.

---

## Security Fix Index

| # | Vulnerability (vulnerable branch) | Fix (this branch) | Files |
|---|---|---|---|
| 1 | Plain-text password storage | bcrypt hashing (cost 12) | `authController.js`, `User.js` |
| 2 | No authentication on routes | JWT `protect` middleware on all routes | `middleware/auth.js`, `routes/*.js` |
| 3 | NoSQL Injection | `express-mongo-sanitize` + whitelisted query params | `server.js`, `routes/services.js` |
| 4 | Mass assignment / privilege escalation | Joi validation + `strict: true` + server-side `owner` | `middleware/validate.js`, all models |
| 5 | Weak & hardcoded JWT secret | Strong env-only secret + 7-day expiry | `authController.js`, `.env.example` |
| 6 | No rate limiting | Global limiter + strict auth limiter | `server.js` |
| 7 | No security headers | Helmet | `server.js` |
| 8 | Overly permissive CORS | Restricted to `ALLOWED_ORIGIN` env variable | `server.js` |
| 9 | Detailed error messages | Generic responses + server-side logging only | `server.js`, all controllers |
| 10 | No input validation | Joi schemas on every route | `middleware/validate.js`, all routes |

---

## Security Fixes — Deep Dive

---

### 1. Password Hashing with bcrypt

**Vulnerable code (`authController.js`):**
```js
const user = await User.create(req.body); // password stored as plain text
if (user.password !== password) { ... }  // plain text comparison
```

**Secure code:**
```js
const hashedPassword = await bcrypt.hash(password, 12);
const user = await User.create({ username, email, password: hashedPassword });

const isMatch = await bcrypt.compare(password, user.password);
```

**Why this matters:**

Plain-text storage means that anyone who gains read access to the database — through injection, a misconfigured backup, an exposed admin panel, or a stolen snapshot — immediately has every user's real password.

`bcrypt` is a purpose-built password hashing function with three properties that make it the right tool:

- **One-way:** It is computationally infeasible to reverse a bcrypt hash back to the original password.
- **Salted:** bcrypt automatically generates and embeds a unique random salt per hash. Two users with the same password produce completely different hashes, making precomputed rainbow table attacks useless.
- **Adjustable cost factor:** The cost factor (12 here) controls how many internal rounds of hashing are performed. At cost 12, a single hash takes ~300ms on modern hardware. This is imperceptible to a legitimate user logging in once, but makes brute-forcing a stolen hash database impractical — an attacker can only try ~3 guesses per second per core.

**Why cost 12 specifically:**
- Cost 10 (~75ms) is a common minimum, but hardware gets cheaper every year.
- Cost 12 (~300ms) offers a comfortable balance between UX and resistance to offline attacks.
- Cost 14+ (~1s) is appropriate for very high-security systems but may feel slow to users.

---

### 2. Route Authentication with JWT Middleware

**Vulnerable code (`routes/devices.js`):**
```js
// No authentication middleware

router.get('/', async (req, res) => { ... });   // public
router.post('/', async (req, res) => { ... });  // public
```

**Secure code:**
```js
// middleware/auth.js
const protect = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: 'Unauthorized' });
  }
};

// routes/devices.js
router.use(protect); // applied once, covers all routes below
```

**Why this matters:**

Without authentication middleware, any HTTP client that can reach port 5000 — a script, a browser, another service on the same network — has full read/write access to all data. There is nothing to attack; the data is simply open.

The `protect` middleware enforces a three-step gate on every request:
1. **Is a token present?** If not, reject immediately with 401.
2. **Is the token signature valid?** `jwt.verify()` checks the HMAC-SHA256 signature against the secret. A token that was forged, tampered with, or signed with a different secret fails here.
3. **Is the token within its expiry window?** An expired token is rejected even if the signature is valid.

Only requests that pass all three checks receive a `req.user` object and reach the controller.

**Why a single `router.use(protect)` instead of adding it to each route individually:**
- It is easy to forget to add middleware to a new route. Placing `router.use(protect)` once at the top of the router file means any route added in the future is automatically protected.

**Why the same `'Unauthorized'` message for both missing and invalid tokens:**
- Different messages (`'No token provided'` vs `'Invalid token'` vs `'Token expired'`) help an attacker understand the shape of the system. A single generic message reveals nothing.

---

### 3. NoSQL Injection Prevention

**Vulnerable code (`routes/services.js`):**
```js
// req.query is passed directly into find() — operator injection possible
const services = await Service.find(req.query);
```

**Attack that was possible:**
```bash
# Dump all services by injecting the $gt operator
GET /api/services?vulnerabilityScore[$gt]=0

# Bypass status filters
GET /api/services?status[$ne]=inactive
```

**Secure code:**
```js
// server.js — strips MongoDB operators from ALL incoming data globally
app.use(mongoSanitize());

// routes/services.js — only accepts a known, validated query parameter
const filter = { owner: req.user.id };

if (req.query.device) {
  if (!/^[a-fA-F0-9]{24}$/.test(req.query.device)) {
    return res.status(400).json({ message: 'Invalid device id' });
  }
  filter.device = req.query.device;
}

const services = await Service.find(filter);
```

**Why this matters:**

MongoDB query operators (`$gt`, `$lt`, `$ne`, `$where`, `$regex`, etc.) are valid JSON keys. If a user-supplied object is passed directly to `find()`, a client can include these operators to manipulate the query logic — bypassing filters, extracting records they should not see, or in the case of `$where` (which evaluates JavaScript server-side), potentially achieving remote code execution.

Two layers of defence are used here:

1. **`express-mongo-sanitize`** (global, `server.js`): Walks every incoming `req.body`, `req.params`, and `req.query` object and removes any key that starts with `$` or contains a `.`. This prevents operator injection across the entire application automatically, not just on this one route.

2. **Whitelisted query parameters** (per-route, `routes/services.js`): Instead of forwarding `req.query` to `find()`, a clean `filter` object is built manually. Only the `device` parameter is accepted, and it must match a strict ObjectId regex before use. All other query parameters are silently ignored.

Defence-in-depth: if one layer fails or is misconfigured, the other still holds.

---

### 4. Mass Assignment & Privilege Escalation Prevention

**Vulnerable code (`models/User.js`, `routes/devices.js`):**
```js
// strict: false in every model — Mongoose stores ANY field the client sends
const userSchema = new mongoose.Schema({ ... }, { strict: false });

// req.body passed directly to create() — client controls all fields
const user = await User.create(req.body);
```

**Attack that was possible:**
```bash
# Self-promote to admin at registration
POST /api/auth/register
{ "username": "hacker", "email": "h@x.com", "password": "pw", "role": "admin", "isAdmin": true }
```

**Secure code:**
```js
// models/User.js — strict: true (Mongoose default), role restricted to enum
const userSchema = new mongoose.Schema({
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
}, { strict: true });

// middleware/validate.js — stripUnknown removes unrecognised fields
const { error } = schema.validate(req.body, { stripUnknown: true });

// controllers/authController.js — only known fields are destructured
const { username, email, password } = req.body;
const user = await User.create({ username, email, password: hashedPassword });

// routes/devices.js — owner is set from the JWT, never from req.body
const device = await Device.create({ ...req.body, owner: req.user.id });
```

**Why this matters:**

Mass assignment is a vulnerability where a client supplies extra fields in a request body that the application blindly saves to the database. Combined with `strict: false` (which told Mongoose to accept any field), an attacker could set `isAdmin: true`, override another user's `owner`, or store arbitrary data in any field.

Three coordinated layers close this:

1. **Joi + `stripUnknown: true`** (middleware layer): The validation schema defines the allowed fields. Any field not in the schema is silently stripped before the data reaches the controller. `isAdmin`, `role`, `owner`, `apiKey` — sent by an attacker — never survive this step.

2. **`strict: true`** (model layer): Even if an unexpected field somehow reached `Model.create()`, Mongoose would silently ignore it. This is the Mongoose default and is explicitly set in every model for clarity.

3. **Server-side `owner` assignment** (controller layer): The `owner` field (which links a record to a user) is always set to `req.user.id` — the value decoded from the verified JWT. The client never supplies it. Even if an attacker crafts a body with `"owner": "someOtherId"`, Joi strips it, and the controller overwrites it with the real value anyway.

---

### 5. Strong JWT Secret & Token Expiry

**Vulnerable code (`.env.example`, `authController.js`):**
```js
JWT_SECRET=superweaksecret123  // committed to the repo, 18 characters

const token = jwt.sign({ id: user._id }, JWT_SECRET); // no expiry
```

**Secure code:**
```js
// .env.example — placeholder only, real value never committed
JWT_SECRET=replace_with_a_long_random_secret_min_64_chars

// authController.js
const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
  expiresIn: '7d',
});
```

**Generate a proper secret:**
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# outputs 128 hex characters (512 bits of entropy)
```

**Why this matters:**

A JWT is only as trustworthy as the secret used to sign it. `jwt.sign()` uses HMAC-SHA256, which means anyone who knows the secret can produce a valid token for any payload — including `{ "id": "any-user-id", "role": "admin" }`.

`superweaksecret123` fails on multiple fronts:
- **Committed to version control:** It is now in git history forever, accessible to anyone who has ever cloned the repo.
- **Too short:** At 18 characters it has far less entropy than the 256+ bits HMAC-SHA256 can use. A GPU cluster can exhaust short secrets quickly.
- **Dictionary-adjacent:** Tools like `hashcat` with JWT cracking wordlists would find it in seconds.

A 64-byte (128 hex character) secret generated by `crypto.randomBytes` has 512 bits of entropy — computationally indistinguishable from random, unpublished, and unique per deployment.

**Why token expiry matters:**

Without `expiresIn`, a stolen token is valid forever. If a user's device is compromised, their session can never be invalidated short of rotating the secret (which would log out every user). A 7-day expiry limits the window of exposure: a stolen token stops working on its own within a week.

---

### 6. Rate Limiting

**Vulnerable code (`server.js`):**
```js
// No rate limiting — every endpoint accepts unlimited requests
```

**Secure code:**
```js
// Global limiter — 100 requests per 15 minutes per IP
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(globalLimiter);

// Strict auth limiter — 10 attempts per 15 minutes per IP
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.use('/api/auth', authLimiter);
```

**Why this matters:**

Without rate limiting, two categories of attack are trivial:

**Brute force:** An attacker targeting a known email address can script login attempts at thousands per second. A 10-character lowercase password has 26^10 ≈ 141 trillion combinations. At 10,000 requests/second (easily achievable on a home connection against an unprotected endpoint) that's ~16 million seconds — but most users choose passwords far weaker than the theoretical maximum, so real attacks succeed much faster.

At 10 auth attempts per 15 minutes, the same attack would take thousands of years for even a modest password.

**Denial of Service:** Without a request cap, a single machine can exhaust the server's CPU, memory, or database connection pool by flooding it with requests. The global limiter caps each IP at 100 requests per window, making volumetric DoS from a single IP impractical.

**Why two separate limiters:**
- The global limiter protects all routes from volumetric abuse.
- Auth routes need a much stricter cap because the cost of a successful brute force (account takeover) is far higher than the cost of a 429 response to a legitimate user who mistyped their password a few times.

---

### 7. Security Headers with Helmet

**Vulnerable code (`server.js`):**
```js
// No Helmet — no protective headers sent
```

**Secure code:**
```js
app.use(helmet());
```

**Why this matters:**

Browsers expose a set of opt-in security mechanisms that are only activated when the server sends the right HTTP response headers. Without them, browsers apply no protections at all.

`helmet()` sets all of the following in one call:

| Header | Attack mitigated |
|---|---|
| `Content-Security-Policy` | Cross-site scripting (XSS) — restricts which scripts, styles, and resources the browser is allowed to load |
| `X-Content-Type-Options: nosniff` | MIME sniffing — prevents the browser from guessing a file's type and executing it as something it isn't |
| `X-Frame-Options: SAMEORIGIN` | Clickjacking — blocks the page from being embedded in an `<iframe>` on a different origin |
| `Strict-Transport-Security` | SSL stripping — tells the browser to always use HTTPS, even if the user typed `http://` |
| `X-XSS-Protection: 0` | Disables the legacy browser XSS auditor (it caused more problems than it solved; CSP replaces it) |
| `Referrer-Policy` | Information leakage — controls how much of the URL is sent in the `Referer` header to third parties |

---

### 8. Restricted CORS Policy

**Vulnerable code (`server.js`):**
```js
app.use(cors({ origin: '*' })); // any website can make requests
```

**Secure code:**
```js
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
```

**Why this matters:**

CORS (Cross-Origin Resource Sharing) is a browser mechanism that controls which external websites are allowed to make JavaScript `fetch()`/`XMLHttpRequest` calls to your API.

With `origin: '*'`, any page on the internet could make requests to your API from a visitor's browser — using the visitor's credentials if they were logged in. A malicious site visited by one of your users could silently read their devices, create records on their behalf, or delete their data.

With a specific origin whitelist:
- Only pages served from `ALLOWED_ORIGIN` (your frontend) receive a valid CORS response.
- Requests from any other origin are blocked at the browser level before the JavaScript even sees the response.
- Restricting `methods` and `allowedHeaders` further reduces the surface area to only what the frontend actually uses.

**Important:** CORS is a browser-only enforcement mechanism. It does not protect against direct API calls made with `curl`, Postman, or server-to-server requests. Authentication (fix #2) is what protects against those.

---

### 9. Generic Error Messages

**Vulnerable code (all controllers):**
```js
res.status(500).json({ error: error.message });
// e.g. → { "error": "Cast to ObjectId failed for value \"abc\" at path \"_id\" for model \"Device\"" }
```

**Secure code:**
```js
// server.js — global error handler
app.use((err, req, res, next) => {
  console.error(err); // full detail logged server-side only
  res.status(500).json({ message: 'Internal server error' }); // generic to client
});

// controllers — errors thrown, not caught locally
throw error; // reaches the global handler above
```

**Why this matters:**

Detailed error messages are a form of information disclosure. They hand attackers a map of your internals:

- `"Cast to ObjectId failed for value \"abc\" at path \"_id\" for model \"Device\""` → reveals the model name, the field name, and the database driver behaviour.
- `"E11000 duplicate key error collection: homelab.users index: email_1"` → reveals the database name, collection name, and indexed field.
- Stack traces reveal file paths, function names, and library versions — all searchable for known CVEs.

The fix separates two concerns:
- **Server-side:** `console.error(err)` logs the full error with stack trace. Developers and monitoring tools can see everything they need to diagnose problems.
- **Client-side:** The response is always `{ "message": "Internal server error" }`. Useful to the client (something went wrong), useless to an attacker.

---

### 10. Input Validation with Joi

**Vulnerable code (all routes):**
```js
const user = await User.create(req.body);    // no shape check
const device = await Device.create(req.body); // no type check
```

**Secure code:**
```js
// routes/auth.js — schema defined alongside the route
const registerSchema = Joi.object({
  username: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().lowercase().required(),
  password: Joi.string().min(8).max(128).required(),
});

router.post('/register', validate(registerSchema), register);

// middleware/validate.js — validates and strips unknown fields
const { error } = schema.validate(req.body, {
  abortEarly: false,
  stripUnknown: true,
});
```

**Why this matters:**

Without input validation, the application has no contract with its callers. Anything can reach the database:
- A `notes` field with 10MB of text that exhausts memory and storage.
- A `port` value of `-1` or `999999` that is not a real TCP port.
- A `status` field containing `<script>alert(1)</script>` that fires as stored XSS when a frontend renders it.
- Missing required fields that cause null-reference errors and crash a handler, leaking details in the error response.

Joi validation runs before any controller logic. A request that fails validation receives a `400 Bad Request` with the specific field errors — the database is never touched. This provides:

- **Type safety:** `Joi.number().integer().min(1).max(65535)` on `port` guarantees the database only ever stores valid port numbers.
- **Length limits:** `Joi.string().max(500)` on `notes` prevents payload-based DoS.
- **Format enforcement:** `Joi.string().email()` rejects malformed addresses before they reach the unique index.
- **Mass assignment prevention** (via `stripUnknown: true`): Fields not declared in the schema are stripped silently. This is the first line of defence against privilege escalation attacks — `isAdmin`, `role`, `owner` injected by a client never survive validation.

---

## Project Structure

```
src/
├── config/
│   └── database.js          # MongoDB connection — exits on failure, no silent fallback
├── controllers/
│   └── authController.js    # Register + login with bcrypt and expiring JWTs
├── middleware/
│   ├── auth.js              # JWT protect middleware — gates all device/service routes
│   └── validate.js          # Joi validation factory with stripUnknown
├── models/
│   ├── Device.js            # strict: true, enums, length limits, server-side owner
│   ├── Service.js           # strict: true, port range, ObjectId device ref
│   └── User.js              # strict: true, unique email, role enum, no plain-text pw
└── routes/
    ├── auth.js              # /register and /login with Joi schemas
    ├── devices.js           # Full CRUD, protected, owner-scoped
    └── services.js          # Full CRUD, protected, owner-scoped, safe query params
```

---

## Branch Comparison

| Feature | `vulnerable` branch | `main` branch (this) |
|---|---|---|
| Password storage | ❌ Plain text | ✅ bcrypt (cost 12) |
| Route authentication | ❌ None | ✅ JWT middleware on all routes |
| Input validation | ❌ None | ✅ Joi schemas with `stripUnknown` |
| Security headers | ❌ None | ✅ Helmet |
| Rate limiting | ❌ None | ✅ Global + strict auth limiter |
| CORS policy | ❌ Wildcard `*` | ✅ Env-configured origin |
| JWT secret | ❌ Hardcoded, weak, no expiry | ✅ Env-only, 512-bit, 7-day expiry |
| Error messages | ❌ Full `error.message` to client | ✅ Generic to client, full server-side log |
| NoSQL sanitization | ❌ `req.query` passed to `find()` | ✅ `mongo-sanitize` + whitelisted params |
| Mongoose strict mode | ❌ `strict: false` on all models | ✅ `strict: true` on all models |
| IDOR protection | ❌ Any record accessible by ID | ✅ All queries scoped to `owner` |
| Mass assignment | ❌ `req.body` straight to `create()` | ✅ Joi strips unknown fields + destructuring |

## 💬 Feedback & Contact

Feedback, ideas, and suggestions are always welcome.

Feel free to reach out:  **Ala Eddine Jebali** — https://alaeddinejebali.com