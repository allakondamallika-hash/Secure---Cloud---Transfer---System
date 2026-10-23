/*
  AI File Risk Scanner
  ---------------------------------------------------------------
  Explainable, rule-weighted risk engine (same style as the node
  detector in server.js). It inspects an uploaded file BEFORE any
  encryption or transfer happens and returns a risk verdict.

  A file is classified HIGH RISK (red signal) when it is:
    1. ANONYMOUS   - no/blank/generic/forged name
    2. UNSUPPORTED - type not on the allow-list, or executable/script
    3. INCOMPLETE  - empty, partial download, or truncated content
    4. MALICIOUS   - content does not match its extension, or it
                     carries an executable signature

  score >= 70  -> HIGH   -> BLOCKED (encryption + transfer stop)
  score 35-69  -> MEDIUM -> allowed with warning
  score < 35   -> LOW    -> allowed (secure)
*/

const fs = require("fs");

const HEAD_BYTES = 4096;
const TAIL_BYTES = 66000; // large enough to find a ZIP end-of-central-directory record
const BLOCK_THRESHOLD = 70;

// Allow-list of supported file types.  kind = how the content is validated.
const SUPPORTED = {
  pdf:  "pdf",
  png:  "png",
  jpg:  "jpeg",
  jpeg: "jpeg",
  gif:  "gif",
  webp: "webp",
  bmp:  "bmp",
  txt:  "text",
  md:   "text",
  csv:  "text",
  json: "json",
  xml:  "text",
  rtf:  "rtf",
  zip:  "zip",
  docx: "zip",
  xlsx: "zip",
  pptx: "zip",
  odt:  "zip",
  doc:  "ole",
  xls:  "ole",
  ppt:  "ole",
  mp3:  "mp3",
  mp4:  "mp4"
};

// Executables / scripts / installers that must never be accepted.
const DANGEROUS_EXT = new Set([
  "exe","dll","bat","cmd","com","scr","msi","ps1","vbs","vbe","js","jse","wsf","wsh",
  "jar","apk","sh","bin","sys","lnk","reg","hta","cpl","pif","iso","dmg","app","deb","rpm"
]);

// Extensions that indicate the file was never fully received.
const PARTIAL_EXT = new Set([
  "crdownload","part","partial","tmp","temp","download","filepart","opdownload","!ut"
]);

const GENERIC_NAMES = new Set([
  "unknown","untitled","anonymous","noname","no-name","unnamed","blob","file","null","undefined"
]);

const TEXT_KINDS = new Set(["text", "json", "rtf"]);

const EXEC_SIGNATURES = [
  { name: "Windows executable (MZ)",    bytes: [0x4d, 0x5a] },
  { name: "Linux executable (ELF)",     bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { name: "Shell script (#!)",          bytes: [0x23, 0x21] },
  { name: "Java class file",            bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { name: "Mach-O executable",          bytes: [0xfe, 0xed, 0xfa, 0xce] },
  { name: "Mach-O executable",          bytes: [0xfe, 0xed, 0xfa, 0xcf] },
  { name: "Mach-O executable",          bytes: [0xce, 0xfa, 0xed, 0xfe] },
  { name: "Mach-O executable",          bytes: [0xcf, 0xfa, 0xed, 0xfe] }
];

function startsWith(buf, bytes, offset = 0) {
  if (!buf || buf.length < offset + bytes.length) return false;
  return bytes.every((b, i) => buf[offset + i] === b);
}
const ascii = (s) => [...s].map((c) => c.charCodeAt(0));

function trimTrailingZeros(buf) {
  let end = buf.length;
  while (end > 0 && buf[end - 1] === 0x00) end--;
  return buf.subarray(0, end);
}

/* Returns true when the header matches the expected type. */
function signatureMatches(kind, head) {
  switch (kind) {
    case "pdf":  return startsWith(head, ascii("%PDF-"));
    case "png":  return startsWith(head, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    case "jpeg": return startsWith(head, [0xff, 0xd8, 0xff]);
    case "gif":  return startsWith(head, ascii("GIF87a")) || startsWith(head, ascii("GIF89a"));
    case "webp": return startsWith(head, ascii("RIFF")) && startsWith(head, ascii("WEBP"), 8);
    case "bmp":  return startsWith(head, ascii("BM"));
    case "zip":  return startsWith(head, [0x50, 0x4b, 0x03, 0x04]);
    case "ole":  return startsWith(head, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    case "rtf":  return startsWith(head, ascii("{\\rtf"));
    case "mp3":  return startsWith(head, ascii("ID3")) || (head.length > 1 && head[0] === 0xff && (head[1] & 0xe0) === 0xe0);
    case "mp4":  return startsWith(head, ascii("ftyp"), 4);
    default:     return true; // text / json / xml have no fixed signature
  }
}

/* Returns a reason string when the content looks cut off, otherwise null. */
function truncationReason(kind, size, head, tail) {
  switch (kind) {
    case "pdf": {
      const end = tail.subarray(Math.max(0, tail.length - 1024)).toString("latin1");
      return end.includes("%%EOF") ? null : "PDF is missing its end-of-file marker (upload incomplete)";
    }
    case "png": {
      const end = tail.subarray(Math.max(0, tail.length - 16)).toString("latin1");
      return end.includes("IEND") ? null : "PNG image is missing its IEND chunk (upload incomplete)";
    }
    case "jpeg": {
      const t = trimTrailingZeros(tail);
      const ok = t.length >= 2 && t[t.length - 2] === 0xff && t[t.length - 1] === 0xd9;
      return ok ? null : "JPEG image is missing its end-of-image marker (upload incomplete)";
    }
    case "gif": {
      const t = trimTrailingZeros(tail);
      return t.length && t[t.length - 1] === 0x3b ? null : "GIF image is missing its trailer byte (upload incomplete)";
    }
    case "webp": {
      if (head.length >= 8) {
        const expected = head.readUInt32LE(4) + 8;
        if (size < expected) return "WebP image is shorter than its declared length (upload incomplete)";
      }
      return null;
    }
    case "bmp": {
      if (head.length >= 6) {
        const expected = head.readUInt32LE(2);
        if (expected > 0 && size < expected) return "BMP image is shorter than its declared length (upload incomplete)";
      }
      return null;
    }
    case "zip": {
      const hasEocd = tail.includes(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
      return hasEocd ? null : "ZIP/Office container has no end-of-archive record (upload incomplete)";
    }
    case "json": {
      const t = tail.toString("utf8").trimEnd();
      const last = t[t.length - 1];
      return last === "}" || last === "]" ? null : "JSON document is cut off before its closing bracket (upload incomplete)";
    }
    case "rtf": {
      const t = tail.toString("latin1").trimEnd();
      return t.endsWith("}") ? null : "RTF document is cut off before its closing brace (upload incomplete)";
    }
    default:
      return null;
  }
}

/**
 * Analyze a file.
 * @param {{name:string,size:number,head:Buffer,tail:Buffer}} f
 */
function analyzeFile({ name, size, head, tail }) {
  head = head || Buffer.alloc(0);
  tail = tail || Buffer.alloc(0);
  const findings = []; // { weight, category, reason }
  const add = (weight, category, reason) => findings.push({ weight, category, reason });

  const rawName = typeof name === "string" ? name : "";
  const cleanName = rawName.trim();
  const lower = cleanName.toLowerCase();
  const parts = lower.split(".");
  const hasExt = parts.length > 1 && parts[parts.length - 1].length > 0;
  const ext = hasExt ? parts[parts.length - 1] : "";
  const stem = hasExt ? parts.slice(0, -1).join(".") : lower;
  const kind = SUPPORTED[ext];

  // ---- 1. ANONYMOUS -------------------------------------------------
  if (!cleanName) {
    add(100, "ANONYMOUS", "Anonymous file: no file name supplied");
  } else {
    if (/[\x00-\x1f]/.test(rawName) || rawName.includes("..") || /[\\/]/.test(rawName)) {
      add(90, "ANONYMOUS", "Anonymous/forged file name: control characters or path-traversal pattern detected");
    }
    if (cleanName.startsWith(".")) {
      add(75, "ANONYMOUS", "Anonymous file: hidden file with no real name");
    } else if (GENERIC_NAMES.has(stem)) {
      add(75, "ANONYMOUS", `Anonymous file: generic/unidentified name "${stem}"`);
    }
  }

  // ---- 2. INCOMPLETE (empty / partial download) ----------------------
  if (!size) add(100, "INCOMPLETE", "Incomplete file: file is empty (0 bytes)");
  if (PARTIAL_EXT.has(ext)) add(90, "INCOMPLETE", `Incomplete file: ".${ext}" marks a partial/unfinished download`);

  // ---- 3. UNSUPPORTED / dangerous ------------------------------------
  if (cleanName && !PARTIAL_EXT.has(ext)) {
    if (DANGEROUS_EXT.has(ext)) {
      add(95, "UNSUPPORTED", `Unsupported file: ".${ext}" is an executable/script type`);
    } else if (!hasExt) {
      add(80, "UNSUPPORTED", "Unsupported file: no file extension, type cannot be verified");
    } else if (!kind) {
      add(80, "UNSUPPORTED", `Unsupported file: ".${ext}" is not an allowed file type`);
    }
    // report.exe.pdf  /  invoice.pdf.exe style disguises
    const inner = parts.slice(1, -1);
    if (inner.some((p) => DANGEROUS_EXT.has(p))) {
      add(80, "MALICIOUS", "Suspicious double extension hiding an executable type");
    }
  }

  // ---- 4. Content inspection -----------------------------------------
  let detectedType = kind || null;
  if (size && head.length) {
    const isText = kind && TEXT_KINDS.has(kind);

    // Executable signatures (skip raw-text types except shebang)
    for (const sig of EXEC_SIGNATURES) {
      if (!startsWith(head, sig.bytes)) continue;
      if (isText && sig.name !== "Shell script (#!)") continue;
      add(100, "MALICIOUS", `Malicious indicator: file content is a ${sig.name}, regardless of its extension`);
      detectedType = "executable";
      break;
    }

    if (kind && detectedType !== "executable") {
      if (!signatureMatches(kind, head)) {
        add(85, "MALICIOUS", `File content does not match its ".${ext}" extension (possible disguised file)`);
      } else {
        const cut = truncationReason(kind, size, head, tail);
        if (cut) add(85, "INCOMPLETE", `Incomplete file: ${cut}`);
      }
      if (isText && head.includes(0x00)) {
        add(80, "MALICIOUS", `Binary data found inside a ".${ext}" text file`);
      }
    }
  }

  if (kind === "zip" && ext === "zip" && !findings.length) {
    add(20, "NOTE", "Archive contents cannot be fully inspected");
  }

  // ---- Verdict --------------------------------------------------------
  const score = Math.min(100, findings.reduce((s, f) => s + f.weight, 0));
  const riskLevel = score >= BLOCK_THRESHOLD ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW";
  const blocked = riskLevel === "HIGH";
  const categories = [...new Set(findings.filter((f) => f.category !== "NOTE").map((f) => f.category))];
  const reasons = findings.length
    ? findings.map((f) => f.reason)
    : ["File name, type, structure and signature verified - no suspicious indicators"];

  return {
    score,
    riskLevel,
    blocked,
    signal: blocked ? "RED" : riskLevel === "MEDIUM" ? "YELLOW" : "GREEN",
    status: blocked ? "BLOCKED" : "CLEAR",
    categories,
    detectedType,
    reasons
  };
}

/* Read the first/last bytes of a file on disk (never loads the whole file). */
function readHeadTail(filePath, size) {
  const fd = fs.openSync(filePath, "r");
  try {
    const headLen = Math.min(HEAD_BYTES, size);
    const tailLen = Math.min(TAIL_BYTES, size);
    const head = Buffer.alloc(headLen);
    const tail = Buffer.alloc(tailLen);
    if (headLen) fs.readSync(fd, head, 0, headLen, 0);
    if (tailLen) fs.readSync(fd, tail, 0, tailLen, size - tailLen);
    return { head, tail };
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = { analyzeFile, readHeadTail, BLOCK_THRESHOLD };
