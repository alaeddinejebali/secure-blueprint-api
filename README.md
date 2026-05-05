# secure-blueprint-api
Secure Node.js/Express API built to manage devices, services, and security findings in my cybersecurity homelab. Demonstrates clean API development and security best practices.

# 🚨 VULNERABLE Homelab API - Educational Version

> **⚠️ WARNING: This version is INTENTIONALLY insecure.**  
> It contains multiple security vulnerabilities for learning and demonstration purposes only.  
> **Do NOT deploy this anywhere.**

This branch demonstrates common security mistakes in Node.js/Express APIs so they can be compared with the secure `main` branch.

---

### Purpose of This Branch

- Showcase real-world vulnerabilities
- Help me (and recruiters) understand the difference between secure and insecure code
- Serve as a teaching tool for cybersecurity awareness

---

### Intentionally Introduced Vulnerabilities

| Vulnerability                    | Location                          | Type of Risk |
|-------------------------------|-----------------------------------|--------------|
| Plain-text password storage   | `User.js` model                   | Credential theft |
| No password hashing           | `authController.js`               | Rainbow table / brute force |
| No authentication on routes   | `devices.js` & `services.js`      | Unauthorized access |
| No input validation           | All routes                        | Injection attacks |
| No security headers           | `server.js`                       | XSS, Clickjacking |
| No rate limiting              | `server.js`                       | Brute force & DoS |
| Weak / hardcoded JWT secret   | `.env.example`                    | Token forgery |
| Detailed error messages       | Controllers                       | Information disclosure |
| No MongoDB sanitization       | `server.js`                       | NoSQL Injection |
| Overly permissive CORS        | `server.js`                       | Cross-origin attacks |

---

### How to Run (Vulnerable Version)

```bash
docker-compose up --build