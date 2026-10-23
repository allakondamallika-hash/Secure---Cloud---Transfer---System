const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { analyzeFile, readHeadTail } = require("./fileScanner");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret-in-production";
const MASTER_KEY = crypto.createHash("sha256")
  .update(process.env.MASTER_KEY || "secure-cloud-demo-master-key")
  .digest();

const ROOT = __dirname;
const DATA = path.join(ROOT, "data");
const UPLOADS = path.join(ROOT, "storage", "uploads");
const ENCRYPTED = path.join(ROOT, "storage", "encrypted");
[DATA, UPLOADS, ENCRYPTED].forEach(d => fs.mkdirSync(d, { recursive: true }));

const db = new sqlite3.Database(path.join(DATA, "secure-cloud.db"));

db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON`);
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    anonymous_id TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    node_url TEXT NOT NULL,
    node_score INTEGER NOT NULL,
    node_status TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_reasons TEXT,
    anonymous_id TEXT NOT NULL,
    encryption_iv TEXT NOT NULL,
    encryption_tag TEXT NOT NULL,
    secret_key_hint TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
});

const upload = multer({
  dest: UPLOADS,
  limits: { fileSize: 20 * 1024 * 1024 }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(ROOT, "public")));

function run(sql, params=[]) {
  return new Promise((resolve, reject) =>
    db.run(sql, params, function(err) {
      if (err) reject(err); else resolve(this);
    })
  );
}
function get(sql, params=[]) {
  return new Promise((resolve, reject) =>
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row))
  );
}
function all(sql, params=[]) {
  return new Promise((resolve, reject) =>
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows))
  );
}

function createAnonymousId(userId, email) {
  return "ANON-" + crypto.createHmac("sha256", MASTER_KEY)
    .update(`${userId}:${email}:${Date.now()}`)
    .digest("hex").slice(0, 16).toUpperCase();
}

function createToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: "8h" });
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Authentication required." });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Session expired. Please login again." });
  }
}

/*
  Explainable AI-style malicious node detection.
  This is a deterministic risk model for a college project demo.
  Higher score = higher risk.
*/
function analyzeNode(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl.includes("://") ? rawUrl : `https://${rawUrl}`);
  } catch {
    return { score: 100, status: "BLOCKED", riskLevel: "HIGH", reasons: ["Invalid node URL"] };
  }

  let score = 5;
  const reasons = [];

  const host = url.hostname.toLowerCase();
  const full = url.href.toLowerCase();

  if (url.protocol !== "https:") {
    score += 30; reasons.push("Node is not using HTTPS");
  }
  if (/(\d{1,3}\.){3}\d{1,3}/.test(host)) {
    score += 12; reasons.push("Direct IP address detected");
  }
  if (host.length > 45) {
    score += 10; reasons.push("Unusually long hostname");
  }
  if (/(login|verify|secure|account|update|free|claim|winner)/.test(host)) {
    score += 12; reasons.push("Suspicious hostname keywords");
  }
  if ((host.match(/\./g) || []).length >= 4) {
    score += 10; reasons.push("Deep subdomain structure");
  }
  if (full.includes("@")) {
    score += 25; reasons.push("URL contains an @ redirection pattern");
  }
  if (url.port && !["443", "80"].includes(url.port)) {
    score += 10; reasons.push("Non-standard port");
  }
  if (/(bit\.ly|tinyurl|ngrok|duckdns|no-ip)/.test(host)) {
    score += 18; reasons.push("Dynamic/shortened host pattern");
  }

  // Demo allow-list for predictable classroom presentation.
  const trusted = ["localhost", "127.0.0.1", "trusted-cloud.example.com", "aws.example.com", "azure.example.com"];
  if (trusted.includes(host)) {
    score = Math.min(score, 15);
    reasons.push("Known trusted demo cloud node");
  }

  score = Math.min(100, score);
  const status = score >= 50 ? "BLOCKED" : "TRUSTED";
  const riskLevel = score >= 70 ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW";
  if (!reasons.length) reasons.push("No suspicious indicators detected");
  return { score, status, riskLevel, reasons, normalizedUrl: url.href };
}

function encryptFile(inputPath, outputPath) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", MASTER_KEY, iv);
  const input = fs.createReadStream(inputPath);
  const output = fs.createWriteStream(outputPath);
  return new Promise((resolve, reject) => {
    input.pipe(cipher).pipe(output);
    output.on("finish", () => {
      resolve({
        iv: iv.toString("hex"),
        tag: cipher.getAuthTag().toString("hex"),
        secretHint: crypto.createHash("sha256").update(MASTER_KEY).digest("hex").slice(0, 10)
      });
    });
    input.on("error", reject);
    output.on("error", reject);
  });
}

async function decryptFile(encryptedPath, outputPath, ivHex, tagHex) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", MASTER_KEY, Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(tagHex, "hex"));
  const input = fs.createReadStream(encryptedPath);
  const output = fs.createWriteStream(outputPath);
  return new Promise((resolve, reject) => {
    input.pipe(decipher).pipe(output);
    output.on("finish", resolve);
    input.on("error", reject);
    decipher.on("error", reject);
    output.on("error", reject);
  });
}

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password || password.length < 6)
      return res.status(400).json({ message: "Name, email and password (6+ characters) are required." });

    const existing = await get("SELECT id FROM users WHERE email=?", [email.toLowerCase()]);
    if (existing) return res.status(409).json({ message: "Email already registered." });

    const hash = await bcrypt.hash(password, 12);
    const tempId = crypto.randomBytes(16).toString("hex");
    const result = await run(
      "INSERT INTO users(name,email,password_hash,anonymous_id) VALUES(?,?,?,?)",
      [name.trim(), email.toLowerCase(), hash, "PENDING-" + tempId]
    );
    const anon = createAnonymousId(result.lastID, email.toLowerCase());
    await run("UPDATE users SET anonymous_id=? WHERE id=?", [anon, result.lastID]);
    const user = await get("SELECT id,name,email,anonymous_id,created_at FROM users WHERE id=?", [result.lastID]);
    res.json({ message: "Registration successful.", token: createToken(user), user });
  } catch (e) {
    res.status(500).json({ message: "Registration failed.", error: e.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await get("SELECT * FROM users WHERE email=?", [(email || "").toLowerCase()]);
    if (!user || !(await bcrypt.compare(password || "", user.password_hash)))
      return res.status(401).json({ message: "Invalid email or password." });
    res.json({
      message: "Login successful.",
      token: createToken(user),
      user: { id: user.id, name: user.name, email: user.email, anonymous_id: user.anonymous_id }
    });
  } catch (e) {
    res.status(500).json({ message: "Login failed." });
  }
});

app.get("/api/auth/me", auth, async (req, res) => {
  const user = await get("SELECT id,name,email,anonymous_id,created_at FROM users WHERE id=?", [req.user.id]);
  res.json({ user });
});

app.get("/api/dashboard", auth, async (req, res) => {
  const stats = await get(`
    SELECT
      COUNT(*) total,
      SUM(CASE WHEN status='SUCCESS' THEN 1 ELSE 0 END) successful,
      SUM(CASE WHEN status='BLOCKED' THEN 1 ELSE 0 END) blocked,
      COALESCE(SUM(size),0) bytes
    FROM transfers WHERE user_id=?`, [req.user.id]);
  const recent = await all(`
    SELECT id,original_name,node_url,node_score,node_status,risk_level,status,created_at
    FROM transfers WHERE user_id=? ORDER BY id DESC LIMIT 8`, [req.user.id]);
  res.json({ stats, recent });
});

app.post("/api/security/check-node", auth, async (req, res) => {
  const result = analyzeNode(req.body.nodeUrl || "");
  res.json(result);
});

/*
  Upload wrapper: an interrupted / oversized upload is reported as a
  HIGH-RISK "incomplete file" instead of a raw server error.
*/
function uploadSingle(req, res, next) {
  upload.single("file")(req, res, err => {
    if (!err) return next();
    const tooLarge = err.code === "LIMIT_FILE_SIZE";
    const reason = tooLarge
      ? "Unsupported file: exceeds the 20 MB limit"
      : "Incomplete file: upload was interrupted before the file was fully received";
    res.status(tooLarge ? 413 : 400).json({
      message: "HIGH RISK file detected. Encryption and transfer were stopped immediately.",
      fileAnalysis: {
        score: 100, riskLevel: "HIGH", blocked: true, signal: "RED", status: "BLOCKED",
        categories: [tooLarge ? "UNSUPPORTED" : "INCOMPLETE"], reasons: [reason]
      }
    });
  });
}

/* Optional pre-check used by the UI right after a file is chosen (header/footer bytes only). */
app.post("/api/security/check-file", auth, (req, res) => {
  const { name, size, head, tail } = req.body || {};
  const toBuf = v => Buffer.from(typeof v === "string" ? v : "", "base64");
  res.json(analyzeFile({ name, size: Number(size) || 0, head: toBuf(head), tail: toBuf(tail) }));
});

app.post("/api/transfer", auth, uploadSingle, async (req, res) => {
  let file;
  try {
    file = req.file;
    if (!file) return res.status(400).json({ message: "Please select a file." });

    const nodeUrl = req.body.nodeUrl || "";
    const user = await get("SELECT anonymous_id FROM users WHERE id=?", [req.user.id]);

    // ---- STEP 5a: AI FILE SECURITY CHECK (runs before encryption) ----
    const { head, tail } = readHeadTail(file.path, file.size);
    const fileAnalysis = analyzeFile({ name: file.originalname, size: file.size, head, tail });

    if (fileAnalysis.blocked) {
      // Stop immediately: discard the upload, never encrypt, never store, never transfer.
      fs.unlinkSync(file.path);
      const result = await run(`
        INSERT INTO transfers(
          user_id,original_name,stored_name,size,node_url,node_score,node_status,risk_level,
          risk_reasons,anonymous_id,encryption_iv,encryption_tag,secret_key_hint,status
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [req.user.id,file.originalname || "(anonymous)","-",file.size,nodeUrl,fileAnalysis.score,"FILE_BLOCKED",
         "HIGH",JSON.stringify(fileAnalysis.reasons),user.anonymous_id,"-","-","-","BLOCKED"]
      );
      return res.status(403).json({
        message: "HIGH RISK file detected by AI check. Encryption and transfer were stopped immediately.",
        transferId: result.lastID,
        fileAnalysis,
        pipeline: {
          login: "SUCCESS",
          anonymousIdentity: "GENERATED",
          authentication: "SUCCESS",
          secretKey: "GENERATED",
          aiSecurityCheck: "HIGH RISK FILE",
          encryption: "STOPPED",
          fileTransfer: "STOPPED",
          cloudStorage: "NOT STARTED",
          status: "BLOCKED"
        }
      });
    }
    // ---- STEP 5b: AI DESTINATION NODE CHECK ----
    const analysis = analyzeNode(nodeUrl);

    if (analysis.status === "BLOCKED") {
      fs.unlinkSync(file.path);
      const result = await run(`
        INSERT INTO transfers(
          user_id,original_name,stored_name,size,node_url,node_score,node_status,risk_level,
          risk_reasons,anonymous_id,encryption_iv,encryption_tag,secret_key_hint,status
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [req.user.id,file.originalname,"-",file.size,nodeUrl,analysis.score,"BLOCKED",
         analysis.riskLevel,JSON.stringify(analysis.reasons),user.anonymous_id,"-","-","-","BLOCKED"]
      );
      return res.status(403).json({
        message: "Transfer blocked because the destination cloud node was classified as malicious/high risk.",
        transferId: result.lastID,
        analysis
      });
    }

    const storedName = `${Date.now()}-${crypto.randomBytes(8).toString("hex")}.enc`;
    const encryptedPath = path.join(ENCRYPTED, storedName);
    const encryption = await encryptFile(file.path, encryptedPath);
    fs.unlinkSync(file.path);

    const result = await run(`
      INSERT INTO transfers(
        user_id,original_name,stored_name,size,node_url,node_score,node_status,risk_level,
        risk_reasons,anonymous_id,encryption_iv,encryption_tag,secret_key_hint,status
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [req.user.id,file.originalname,storedName,file.size,nodeUrl,analysis.score,"TRUSTED",
       analysis.riskLevel,JSON.stringify(analysis.reasons),user.anonymous_id,
       encryption.iv,encryption.tag,encryption.secretHint,"SUCCESS"]
    );

    res.json({
      message: "Secure cloud transfer completed successfully.",
      transferId: result.lastID,
      pipeline: {
        login: "SUCCESS",
        anonymousIdentity: "GENERATED",
        authentication: "SUCCESS",
        secretKey: "GENERATED",
        aiSecurityCheck: "TRUSTED CLOUD",
        encryption: "COMPLETED",
        fileTransfer: "SUCCESSFUL",
        cloudStorage: "COMPLETED",
        status: "SUCCESS"
      },
      analysis,
      fileAnalysis,
      encryption: { algorithm: "AES-256-GCM", secretKeyHint: encryption.secretHint }
    });
  } catch (e) {
    if (file && fs.existsSync(file.path)) fs.unlinkSync(file.path);
    res.status(500).json({ message: "Transfer failed.", error: e.message });
  }
});

app.get("/api/transfers", auth, async (req, res) => {
  const rows = await all(`
    SELECT id,original_name,size,node_url,node_score,node_status,risk_level,
           risk_reasons,anonymous_id,status,created_at
    FROM transfers WHERE user_id=? ORDER BY id DESC`, [req.user.id]);
  res.json(rows.map(r => ({ ...r, risk_reasons: JSON.parse(r.risk_reasons || "[]") })));
});

app.get("/api/transfers/:id", auth, async (req, res) => {
  const row = await get("SELECT * FROM transfers WHERE id=? AND user_id=?", [req.params.id, req.user.id]);
  if (!row) return res.status(404).json({ message: "Transfer not found." });
  row.risk_reasons = JSON.parse(row.risk_reasons || "[]");
  res.json(row);
});

app.get("/api/files/:id/download", auth, async (req, res) => {
  try {
    const row = await get("SELECT * FROM transfers WHERE id=? AND user_id=? AND status='SUCCESS'",
      [req.params.id, req.user.id]);
    if (!row) return res.status(404).json({ message: "Encrypted file not found." });

    const encryptedPath = path.join(ENCRYPTED, row.stored_name);
    if (!fs.existsSync(encryptedPath)) return res.status(404).json({ message: "Stored file missing." });

    const temp = path.join(UPLOADS, `download-${Date.now()}-${crypto.randomBytes(6).toString("hex")}`);
    await decryptFile(encryptedPath, temp, row.encryption_iv, row.encryption_tag);
    res.download(temp, row.original_name, err => {
      if (fs.existsSync(temp)) fs.unlinkSync(temp);
      if (err) console.error(err);
    });
  } catch {
    res.status(500).json({ message: "Unable to decrypt/download file." });
  }
});

app.get("*", (req, res) => res.sendFile(path.join(ROOT, "public", "index.html")));

app.listen(PORT, () => console.log(`Secure Cloud Transfer System running at http://localhost:${PORT}`));
