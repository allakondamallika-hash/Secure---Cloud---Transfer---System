# Secure Cloud Transfer System

Full-stack implementation based on the supplied project workflow:

1. User Login
2. Anonymous Identity Generated
3. Authentication Success
4. Secret Key Generated
5. AI Security Check (file risk scan + destination node check)
6. Encryption
7. File Transfer
8. Cloud Storage
9. Status = SUCCESS / BLOCKED

## Technology
- Frontend: HTML5, CSS3, Vanilla JavaScript
- Backend: Node.js + Express
- Database: SQLite
- Authentication: bcrypt + JWT
- Encryption: AES-256-GCM
- Anonymous identity: HMAC-SHA256
- AI malicious-node detector: explainable weighted risk-scoring engine

## Run

Install Node.js 18+.

```bash
npm install
npm start
```

Open:

http://localhost:5000

Default test flow:
- Register an account
- Login
- Enter a destination cloud node such as `https://trusted-cloud.example.com`
- Upload a file
- Run the security check
- If trusted, encrypt and store the file
- View the transfer in Dashboard

## AI File Risk Check (new)

Before any encryption or transfer, every uploaded file passes the AI file scanner (`fileScanner.js`).
A file is flagged **HIGH RISK (red signal)** and the transfer is **stopped immediately** (nothing is
encrypted, stored or sent) when it is:

| Category | Examples |
|---|---|
| Anonymous | no name, `unknown`, `.hidden`, forged/path-traversal names |
| Unsupported | `.exe`, `.bat`, `.js`, `.sh`, unknown or missing extension, over 20 MB |
| Incomplete | 0-byte file, `.crdownload` / `.part` / `.tmp`, truncated PDF/PNG/JPG/ZIP/DOCX/JSON, interrupted upload |
| Malicious | content does not match the extension, executable signature (MZ/ELF/#!), double extension like `invoice.exe.pdf` |

Score 70+ = HIGH (blocked), 35-69 = MEDIUM (warning), below 35 = LOW (secure, continues to encryption).
Blocked files are recorded in Transfer History as BLOCKED / HIGH. Supported types are listed in `fileScanner.js` (`SUPPORTED`).

## Important project note

The AI detector is implemented as an explainable local risk-scoring model suitable for a college demonstration. It is not a trained production ML model. The storage provider is also simulated by local encrypted storage. To connect AWS S3/Azure/GCP later, replace the storage adapter in `server.js`.

## API
- POST /api/auth/register
- POST /api/auth/login
- GET /api/auth/me
- GET /api/dashboard
- POST /api/security/check-node
- POST /api/security/check-file
- POST /api/transfer
- GET /api/transfers
- GET /api/transfers/:id
- GET /api/files/:id/download
