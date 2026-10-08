/* ============================================================
 * FF ACCOUNT GENERATOR — Cloudflare Worker
 *
 * GET /gen?count=1        → naye UID + password generate karo
 * GET /gen?count=5&activate=1  → generate + activation bhi
 * GET /                  → help / usage
 *
 * app.py ka direct JS port (steps 1-6, optional step 7)
 * Pure Web-standard JS — koi npm dependency nahi.
 * ============================================================ */

// ============================================================
// CONSTANTS (app.py se same)
// ============================================================
const AES_KEY = new Uint8Array([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56]);
const AES_IV  = new Uint8Array([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37]);

const CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3";
const APP_ID        = 100067;

const OAUTH_REGISTER_URL    = "https://100067.connect.garena.com/api/v2/oauth/guest:register";
const OAUTH_TOKEN_URL       = "https://100067.connect.garena.com/oauth/guest/token/grant";
const MAJOR_REGISTER_URL    = "https://loginbp.ppmainecoonghj.com/MajorRegister";
const NEWBIE_URL            = "https://loginbp.ppmainecoonghj.com/ChooseNewbieChoice";
const MAJOR_LOGIN_URL       = "https://loginbp.ppmainecoonghj.com/MajorLogin";
const GENERATE_NICKNAME_URL = "https://loginbp.ppmainecoonghj.com/GenerateNickname";
const GETLOGIN_HOST_IND     = "client.ind.freefiremobile.com";

const REGION = "IND";

const XOR_KEY = new Uint8Array([
  0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
  0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,
]);

const FIELD_22_HEX =
  "474752450101010062020000a78910bd098e3ff2e4345d59a31db114ea088f37e32e65" +
  "212ff96621793d9eb78720d0bf2ac95176569765247ada5eb01376b3b9931794a4946" +
  "d76ef8890779f3f2129317e6e1cb2fdcf7b06247cea343b8d4f167eff85a2e1dfe99" +
  "b4583a7e1a155dbe7f7f85cff3b223eb77222ec1228f3ee1ef6ce7f8ca24b00a554" +
  "e497328812f8df74c82d519ae3e3ceab436eb145e8a517089a7cef6a4efb22214b2" +
  "a4b19989b74807584afe5e52825e7ac60e19a596a9bf02d961de6a0ed2515ec6023" +
  "fdb7684d9464b97b21c527ce61b6bee4ef30d20a1fa33a996952d44d44e44f2f86c" +
  "768aaf2a7808ad60f91048dca0207961ba7c2555c48341b30190debc775edb2cee24" +
  "4cf51fca3760ce4388be2db45e80b813b5beb9c784007b7762d7a1e428affc8a3a4" +
  "cd76cbaef648a274297fde33233dccd3f272cb77f39a1affe0365a24954111f768f72" +
  "0e77535af024bea2b2726c3bac992374755c3deacf09235e6865d456e651680d115a" +
  "751a797225eaacdf9a513cf104526e1a32e5296e111a33ae581a63850837921df848" +
  "9adfd41ea895b7cf3f5b2e45d538a6e4f032f590ccbb7daf5fa9c50adadee0799661" +
  "4c3f957bda349e6c484fdf55970d1943ad7955a76671298b6d98b636b69ebde6bc94" +
  "dbd93ac3393a6ae230130445b2d744189167854a5617be2393e7d8fbb5719a1b4754" +
  "1ba466167e3e05a6c244f1301ee2035acf94dffc8adbde747d5cd85e35ead3acc372" +
  "a59c4220e54bf63f9d80485f3de2518495c1d0f78c911d2da595911fd2a1989cf17" +
  "cf3ded5f6c92dea64d675c555c11df92d6c517ca5d0d61a8962f43f76ec7e87596c" +
  "8325ebf9ab0f8e6d2eca33c511ceac6980906ebd68c478665591dcecf788ec6ef34c" +
  "fbe3fcc279c6147c5bf91cd43cdc9704236";

const FIELD_22 = hexToBytes(FIELD_22_HEX);

// ============================================================
// AES-128-CBC (pure JS — Workers me padding control chahiye)
// ============================================================
const S_BOX = new Uint8Array([
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);

const SI_BOX = new Uint8Array([
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
]);

function xtime(a) {
  return ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;
}

function mul(a, n) {
  let r = 0;
  while (n) {
    if (n & 1) r ^= a;
    a = xtime(a);
    n >>= 1;
  }
  return r;
}

function expandKey(key) {
  const w = new Uint8Array(176);
  w.set(key);
  let rcon = 1;
  for (let i = 16; i < 176; i += 4) {
    let t0 = w[i - 4], t1 = w[i - 3], t2 = w[i - 2], t3 = w[i - 1];
    if (i % 16 === 0) {
      // RotWord + SubWord + Rcon (sirf har 4th word pe)
      t0 = S_BOX[w[i - 3]] ^ rcon;
      t1 = S_BOX[w[i - 2]];
      t2 = S_BOX[w[i - 1]];
      t3 = S_BOX[w[i - 4]];
      rcon = xtime(rcon);
    }
    w[i]     = w[i - 16] ^ t0;
    w[i + 1] = w[i - 15] ^ t1;
    w[i + 2] = w[i - 14] ^ t2;
    w[i + 3] = w[i - 13] ^ t3;
  }
  return w;
}

const RK = expandKey(AES_KEY); // AES_KEY static hai, ek baar expand

function addRoundKey(s, off) {
  for (let i = 0; i < 16; i++) s[i] ^= RK[off + i];
}

function subBytes(s)   { for (let i = 0; i < 16; i++) s[i] = S_BOX[s[i]]; }
function invSubBytes(s){ for (let i = 0; i < 16; i++) s[i] = SI_BOX[s[i]]; }

function shiftRows(s) {
  let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
  t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
  t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

function invShiftRows(s) {
  let t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
  t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
  t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

function mixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
    s[4 * c]     = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
    s[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
    s[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
    s[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
  }
}

function invMixColumns(s) {
  for (let c = 0; c < 4; c++) {
    const a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
    s[4 * c]     = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9);
    s[4 * c + 1] = mul(a0, 9)  ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13);
    s[4 * c + 2] = mul(a0, 13) ^ mul(a1, 9)  ^ mul(a2, 14) ^ mul(a3, 11);
    s[4 * c + 3] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9)  ^ mul(a3, 14);
  }
}

function aesEncryptBlock(block) {
  const s = new Uint8Array(block);
  addRoundKey(s, 0);
  for (let r = 1; r < 10; r++) {
    subBytes(s); shiftRows(s); mixColumns(s); addRoundKey(s, r * 16);
  }
  subBytes(s); shiftRows(s); addRoundKey(s, 160);
  return s;
}

function aesDecryptBlock(block) {
  const s = new Uint8Array(block);
  addRoundKey(s, 160);
  for (let r = 9; r > 0; r--) {
    invShiftRows(s); invSubBytes(s); addRoundKey(s, r * 16); invMixColumns(s);
  }
  invShiftRows(s); invSubBytes(s); addRoundKey(s, 0);
  return s;
}

function pkcs7Pad(data) {
  const padLen = 16 - (data.length % 16);
  const out = new Uint8Array(data.length + padLen);
  out.set(data);
  out.fill(padLen, data.length);
  return out;
}

function pkcs7Unpad(data) {
  if (!data.length || data.length % 16 !== 0) return data;
  const p = data[data.length - 1];
  if (p < 1 || p > 16) return data;
  for (let i = data.length - p; i < data.length; i++) if (data[i] !== p) return data;
  return data.subarray(0, data.length - p);
}

function aesEncrypt(plain) {
  const data = pkcs7Pad(plain);
  const out = new Uint8Array(data.length);
  let prev = AES_IV;
  for (let i = 0; i < data.length; i += 16) {
    const blk = new Uint8Array(16);
    for (let j = 0; j < 16; j++) blk[j] = data[i + j] ^ prev[j];
    const enc = aesEncryptBlock(blk);
    out.set(enc, i);
    prev = enc;
  }
  return out;
}

function aesDecrypt(ciphertext) {
  if (!ciphertext || ciphertext.length % 16 !== 0) return ciphertext;
  const out = new Uint8Array(ciphertext.length);
  let prev = AES_IV;
  for (let i = 0; i < ciphertext.length; i += 16) {
    const blk = ciphertext.subarray(i, i + 16);
    const dec = aesDecryptBlock(blk);
    for (let j = 0; j < 16; j++) out[i + j] = dec[j] ^ prev[j];
    prev = blk;
  }
  return pkcs7Unpad(out);
}

// ============================================================
// HELPERS
// ============================================================
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: false });

function utf8(s) { return enc.encode(s); }

function bytesToHex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function nowSec() { return Math.floor(Date.now() / 1000); }
function timestamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
         `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}
function randInt(min, max) {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return min + (buf[0] % (max - min + 1));
}
function randIp() { return `${randInt(1, 223)}.${randInt(1, 255)}.${randInt(1, 255)}.${randInt(1, 255)}`; }

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest)).toUpperCase();
}

async function hmacSha256Hex(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, utf8(msg));
  return bytesToHex(new Uint8Array(sig));
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function retry(fn, retries = 3) {
  let last;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (e) {
      last = e;
      if (attempt < retries) {
        // 429 (rate limit) pe zyada wait karo
        const is429 = /429|too_many/.test(e.message);
        const base = is429 ? 4000 : 1000;
        await sleep(base * Math.pow(2, attempt - 1));
      }
    }
  }
  throw new Error(`retry exhausted: ${last && last.message}`);
}

function xorOpenId(openId) {
  const b = utf8(openId);
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b[i] ^ XOR_KEY[i % XOR_KEY.length];
  return out;
}

// ============================================================
// PROTOBUF WRITER / READER
// ============================================================
function writeVarint(value) {
  const out = [];
  while (value > 127) {
    out.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  out.push(value);
  return new Uint8Array(out);
}

function concatBytes(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function assembleProto(fields) {
  const parts = [];
  for (const key of Object.keys(fields)) {
    const f = Number(key);
    const v = fields[f];
    if (typeof v === "number") {
      parts.push(writeVarint(f << 3), writeVarint(v));
    } else if (typeof v === "string") {
      const b = utf8(v);
      parts.push(writeVarint((f << 3) | 2), writeVarint(b.length), b);
    } else if (v instanceof Uint8Array) {
      parts.push(writeVarint((f << 3) | 2), writeVarint(v.length), v);
    }
  }
  return concatBytes(...parts);
}

function readVarint(data, offset) {
  let r = 0, s = 0;
  while (offset < data.length) {
    const b = data[offset]; offset++;
    r |= (b & 0x7f) << s;
    if (!(b & 0x80)) break;
    s += 7;
  }
  return [r >>> 0, offset];
}

function parseProto(data) {
  const out = {};
  let off = 0;
  while (off < data.length) {
    let tag;
    try { [tag, off] = readVarint(data, off); } catch { break; }
    const f = tag >>> 3;
    const w = tag & 0x7;
    if (f === 0) break;
    try {
      if (w === 0) {
        let v; [v, off] = readVarint(data, off);
        out[f] = v;
      } else if (w === 2) {
        let ln; [ln, off] = readVarint(data, off);
        const val = data.subarray(off, off + ln);
        off += ln;
        try { out[f] = dec.decode(val); }
        catch { out[f] = bytesToHex(val); }
      } else break;
    } catch { break; }
  }
  return out;
}

// ============================================================
// STEP 1 — Register guest
// ============================================================
async function registerGuest(password) {
  const payload = { app_id: APP_ID, client_type: 2, password, source: 2 };
  const body = JSON.stringify(payload);
  const sig = await hmacSha256Hex(CLIENT_SECRET, body);
  const r = await fetch(OAUTH_REGISTER_URL, {
    method: "POST",
    headers: {
      "User-Agent": "GarenaMSDK/4.0.42(KB2003 ;Android 13;en;HK;app 2.130.1 2019118332;)",
      "Accept": "application/json",
      "Content-Type": "application/json; charset=utf-8",
      "Connection": "Keep-Alive",
      "Authorization": `Signature ${sig}`,
    },
    body,
  });
  if (r.status !== 200) {
    const t = await r.text().catch(() => "");
    throw new Error(`register HTTP ${r.status}: ${t.slice(0, 200)}`);
  }
  const d = await r.json();
  if (d.code !== 0) throw new Error(`register failed: ${d.error || d.message} (code ${d.code})`);
  return String(d.data.uid);
}

// ============================================================
// STEP 2 — Token grant
// ============================================================
async function getToken(uid, password) {
  const body = new URLSearchParams({
    uid, password,
    response_type: "token",
    client_type: "2",
    client_secret: CLIENT_SECRET,
    client_id: String(APP_ID),
  });
  const r = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers: {
      "User-Agent": "GarenaMSDK/4.0.30",
      "Accept": "application/json",
      "Connection": "Keep-Alive",
    },
    body,
  });
  if (r.status !== 200) {
    const t = await r.text().catch(() => "");
    throw new Error(`token HTTP ${r.status}: ${t.slice(0, 200)}`);
  }
  const d = await r.json();
  if (!d.access_token || !d.open_id) throw new Error("token missing fields");
  return { accessToken: d.access_token, openId: d.open_id };
}

// ============================================================
// STEP 3 — GenerateNickname
// ============================================================
async function generateNickname(openId) {
  const plain = assembleProto({ 1: "en", 2: openId });
  const encrypted = aesEncrypt(plain);
  const r = await fetch(GENERATE_NICKNAME_URL, {
    method: "POST",
    headers: {
      "Authorization": "Bearer",
      "Content-Type": "application/x-www-form-urlencoded",
      "ReleaseVersion": "OB55",
      "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
      "X-GA": "v1 1",
      "X-Unity-Version": "2018.4.12f1",
    },
    body: encrypted,
  });
  if (r.status !== 200) throw new Error(`nickname HTTP ${r.status}: ${(await r.text().catch(() => "")).slice(0, 150)}`);
  const name = (await r.text().catch(() => "")).trim();
  if (!name) throw new Error("empty nickname");
  return name;
}

// ============================================================
// STEP 4 — MajorRegister
// ============================================================
async function sendMajorRegister(nickname, accessToken, openId) {
  const fields = {
    1:  nickname,
    2:  accessToken,
    3:  openId,
    5:  102000007,
    6:  4,
    7:  1,
    13: 1,
    14: xorOpenId(openId),
    15: "TW",
    16: 2,
    20: "2.133.8",
    21: 1,
    22: FIELD_22,
  };
  const encrypted = aesEncrypt(assembleProto(fields));
  const r = await fetch(MAJOR_REGISTER_URL, {
    method: "POST",
    headers: {
      "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
      "Accept": "*/*",
      "X-GA-SV": String(nowSec()),
      "Authorization": "Bearer",
      "X-GA": "v1 1",
      "ReleaseVersion": "OB55",
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Unity-Version": "2018.4.12f1",
    },
    body: encrypted,
  });
  if (r.status !== 200) throw new Error(`majorregister HTTP ${r.status}: ${(await r.text().catch(() => "")).slice(0, 150)}`);
  const parsed = parseProto(new Uint8Array(await r.arrayBuffer()));
  const aid = parsed[3];
  if (!aid) throw new Error("no account_id");
  return Number(aid);
}

// ============================================================
// STEP 5 — ChooseNewbieChoice
// ============================================================
async function sendNewbie(accountId, choice = 3) {
  const plain = assembleProto({ 1: Number(accountId), 2: 1, 3: Number(choice) });
  const encrypted = aesEncrypt(plain);
  const r = await fetch(NEWBIE_URL, {
    method: "POST",
    headers: {
      "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
      "Accept": "*/*",
      "X-GA-SV": String(nowSec()),
      "Authorization": "Bearer",
      "X-GA": "v1 1",
      "ReleaseVersion": "OB55",
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Unity-Version": "2018.4.12f1",
    },
    body: encrypted,
  });
  if (r.status !== 200) throw new Error(`newbie HTTP ${r.status}`);
  return true;
}

// ============================================================
// STEP 6 — MajorLogin (JWT + session key/iv)
// ============================================================
function findJwt(parsed) {
  let jwt = parsed[8];
  if (jwt instanceof Uint8Array) jwt = dec.decode(jwt);
  if (typeof jwt === "string" && jwt.startsWith("eyJ") && jwt.split(".").length === 3) return jwt;
  return null;
}

function findSessionKeyIv(parsed) {
  const sixteen = [];
  for (const k of Object.keys(parsed).map(Number).sort((a, b) => a - b)) {
    const v = parsed[k];
    if (v instanceof Uint8Array && v.length === 16) sixteen.push(v);
  }
  if (sixteen.length >= 2) {
    return { key: sixteen[sixteen.length - 2], iv: sixteen[sixteen.length - 1] };
  }
  return { key: AES_KEY, iv: AES_IV };
}

async function sendMajorLogin(accessToken, openId, platform = "4") {
  const fields = {
    3:  timestamp(),
    4:  "free fire", 5: 1, 7: "2.133.9",
    8:  "Android OS 10 / API-29 (QP1A.190711.020/1617006012)",
    9:  "Handheld", 10: "Vi India", 11: "WIFI",
    12: 1600, 13: 720, 14: "320",
    15: "ARM64 FP ASIMD AES | 2301 | 8", 16: 2799,
    17: "PowerVR Rogue GE8320",
    18: "OpenGL ES 3.2 build 1.11@5425693",
    19: "Google|9f7d6b8b-b10c-454a-852d-06332cd498eb",
    20: randIp(),
    21: "en", 22: openId, 23: String(platform),
    24: "Handheld", 25: "realme RMX2189", 26: "TW",
    29: accessToken, 30: 1,
    41: "Vi India", 42: "WIFI",
    57: "1ac4b80ecf0478a44203bf8fac6120f5",
    60: 19799, 61: 2536, 62: 5056, 64: 2768,
    65: 19999, 66: 2536, 67: 19799,
    73: 1,
    74: "/data/app/com.dts.freefiremax-ShI7E0dK8p1IiZ785pvuVQ==/lib/arm64",
    76: 2,
    77: "38f4751a330688ab124c2c804cec90a5|/data/app/com.dts.freefiremax-ShI7E0dK8p1IiZ785pvuVQ==/base.apk",
    78: 2, 79: 2, 81: "64", 83: "2019118527",
    86: "OpenGLES3", 87: 3071, 88: 4, 92: 67920,
    93: "android_max",
    94: "KqsHT+UrR1HKqb6+1db+Ofei+NtZr2+hbiBo3yKDL8w+8E3S5qF2IgEEe1fFQFyHRzl4iyHjHp+QsfeLbjJ6+DidTiKxm0ak2uYYa6QR4nAUdlZR",
    95: 111107,
    96: '{"cur_rate":null,"support_etc2":true}',
    97: 1, 98: 1, 99: "4", 100: "4", 102: "",
    104: 83812, 105: 1,
    106: "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a",
    107: "1.9393e7b8e53e8aeb",
  };
  const encrypted = aesEncrypt(assembleProto(fields));
  const r = await fetch(MAJOR_LOGIN_URL, {
    method: "POST",
    headers: {
      "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
      "Accept": "*/*",
      "X-GA-SV": String(nowSec()),
      "Authorization": "Bearer",
      "X-GA": "v1 1",
      "ReleaseVersion": "OB55",
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Unity-Version": "2018.4.12f1",
    },
    body: encrypted,
  });
  if (r.status !== 200) throw new Error(`majorlogin HTTP ${r.status}: ${(await r.text().catch(() => "")).slice(0, 150)}`);

  const raw = new Uint8Array(await r.arrayBuffer());
  const candidates = [aesDecrypt(raw), raw.length > 64 ? raw.slice(64) : null, raw];
  for (const buf of candidates) {
    if (!buf || !buf.length) continue;
    let parsed;
    try { parsed = parseProto(buf); } catch { continue; }
    const jwt = findJwt(parsed);
    if (jwt) {
      const { key, iv } = findSessionKeyIv(parsed);
      return { jwt, sessionKey: bytesToHex(key), sessionIv: bytesToHex(iv) };
    }
  }
  throw new Error("no JWT");
}

// ============================================================
// STEP 7 — GetLoginData (ACTIVATION)
// ============================================================
async function sendGetLoginData(jwt, openId, platform = "4") {
  const fields = {
    3:  timestamp(), 4: "free fire", 5: 1, 7: "2.133.9",
    8:  "Android OS 15 / API-35 (V2UUIS35.39-21-7-5-1-5/319a58-a9271)",
    9:  "Handheld", 10: "airtel", 11: "CarrierDataNetwork",
    12: 2400, 13: 1080, 14: "400",
    15: "ARM64 FP ASIMD AES | 4800 | 8", 16: 7461,
    17: "Adreno (TM) 710",
    18: "OpenGL ES 3.2 V@0615.98 (GIT@0c393b63cf, I94e2bd5684, 1746191168) (Date:05/02/25)",
    19: "Google|0ea5b865-94e6-42dd-9f40-f52a63378bc7",
    20: "27.59.76.15", 21: "en",
    22: openId, 23: String(platform),
    24: "Handheld", 25: "motorola moto g96 5G", 26: "TW",
    29: jwt, 30: 1,
    41: "airtel", 42: "4G",
    57: "1ac4b80ecf0478a44203bf8fac6120f5",
    60: 111316, 61: 73226, 62: 690, 64: 73354,
    65: 111316, 66: 73354, 67: 111316,
    73: 3,
    74: "/data/app/~~xI7rymUmXZFbQjaBVyScAw==/com.dts.freefiremax-lX62T7VsUJ9zo5dV1_axug==/lib/arm64",
    76: 2,
    77: "38f4751a330688ab124c2c804cec90a5|/data/app/~~xI7rymUmXZFbQjaBVyScAw==/com.dts.freefiremax-lX62T7VsUJ9zo5dV1_axug==/base.apk",
    78: 2, 79: 2, 81: "64", 83: "2019118527", 85: 3,
    86: "OpenGLES3", 87: 4095, 88: 4,
    90: "New Delhi", 91: "DL", 92: 12573, 93: "android_max",
    94: "KqsHT0wswggWbev04P17TGvl/w+c875HviaAj4qL+YhymI7Psonj/aQgNTNLf+4nm1LzYE6DxxzpZH9FX0Kt119zYuGdivC/V7aWpj4/HNhVAwJy",
    95: 111107,
    96: '{"cur_rate":[60,90,120,144],"support_etc2":true}',
    97: 1, 99: "0", 100: "4", 102: "",
    104: 95926, 105: 1,
    106: "https://dl.cdn.freefiremobile.com/live/ABHotUpdates/|https://dl-core.cdn.freefiremobile.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a",
    107: "1.7a99d677ab872769",
  };
  const encrypted = aesEncrypt(assembleProto(fields));
  const r = await fetch(`https://${GETLOGIN_HOST_IND}/GetLoginData`, {
    method: "POST",
    headers: {
      "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
      "Accept": "*/*",
      "X-GA-SV": String(nowSec()),
      "Authorization": `Bearer ${jwt}`,
      "X-GA": "v1 1",
      "ReleaseVersion": "OB55",
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Unity-Version": "2018.4.12f1",
    },
    body: encrypted,
  });
  if (r.status !== 200) throw new Error(`getlogindata HTTP ${r.status}`);

  const raw = new Uint8Array(await r.arrayBuffer());
  const candidates = [aesDecrypt(raw), raw.length > 64 ? raw.slice(64) : null, raw];
  for (const buf of candidates) {
    if (!buf || !buf.length) continue;
    let p;
    try { p = parseProto(buf); } catch { continue; }
    let online = p[14];
    if (online instanceof Uint8Array) online = dec.decode(online);
    if (online && String(online).includes(":")) {
      let chat = p[32];
      if (chat instanceof Uint8Array) chat = dec.decode(chat);
      return { online: String(online), chat: chat ? String(chat) : null };
    }
  }
  throw new Error("no gateway");
}

// ============================================================
// GENERATE ONE ACCOUNT (steps 1-6 + optional 7)
// ============================================================
async function generateOne(activate, retries = 3) {
  const password = await sha256Hex(crypto.getRandomValues(new Uint8Array(32)));

  // 1) register
  const uid = await retry(() => registerGuest(password), retries);

  // 2) token
  const { accessToken, openId } = await retry(() => getToken(uid, password), retries);

  // 3) nickname
  const nickname = await retry(() => generateNickname(openId), retries);

  // 4) major register
  const accountId = await retry(() => sendMajorRegister(nickname, accessToken, openId), retries);

  // 5) newbie
  await retry(() => sendNewbie(accountId, 3), retries);

  // 6) major login
  const { jwt, sessionKey, sessionIv } = await retry(() => sendMajorLogin(accessToken, openId), retries);

  const account = {
    uid,
    password,
    nickname,
    open_id: openId,
    access_token: accessToken,
    account_id: accountId,
    region: REGION,
    jwt,
    session_key: sessionKey,
    session_iv: sessionIv,
    activated: false,
    created_at: timestamp(),
  };

  // 7) activation (optional)
  if (activate) {
    try {
      const res = await retry(() => sendGetLoginData(jwt, openId, "4"), retries);
      account.online_ip_port = res.online;
      account.chat_ip_port = res.chat;
      account.activated = true;
      account.activated_at = timestamp();
    } catch (e) {
      console.log(`activate failed ${uid}: ${e.message}`);
    }
  }

  return account;
}

// ============================================================
// CONCURRENCY POOL
// ============================================================
async function pool(n, limit, fn) {
  const out = new Array(n);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, n) }, async () => {
    while (next < n) {
      const idx = next++;
      try {
        out[idx] = { ok: true, account: await fn(idx) };
      } catch (e) {
        console.log(`[${idx + 1}] failed: ${e.message}`);
        out[idx] = { ok: false, error: e.message };
      }
    }
  });
  await Promise.all(runners);
  return out;
}

// ============================================================
// WORKER ENTRY
// ============================================================
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    // ── help ──
    if (url.pathname === "/" || url.pathname === "/help") {
      return json({
        success: true,
        service: "FF Account Generator API",
        region: REGION,
        endpoints: {
          "/gen?count=1": "Naye UID + password generate karo",
          "/gen?count=5": "5 accounts ek saath",
          "/gen?count=1&activate=1": "Generate + activation (GetLoginData)",
          "/gen?count=1&retries=5": "Retries per step badhao (max 8)",
          "/debug": "Sirf register step test karo — poora response dikhega",
        },
        limits: { count: "jitna doge utna (default 1)" },
        fields: ["uid", "password", "nickname", "open_id", "access_token", "account_id", "jwt", "session_key", "session_iv"],
      });
    }

    // ── debug: sirf register step, poora response ──
    if (url.pathname === "/debug") {
      const password = await sha256Hex(crypto.getRandomValues(new Uint8Array(32)));
      const payload = { app_id: APP_ID, client_type: 2, password, source: 2 };
      const body = JSON.stringify(payload);
      const sig = await hmacSha256Hex(CLIENT_SECRET, body);
      try {
        const r = await fetch(OAUTH_REGISTER_URL, {
          method: "POST",
          headers: {
            "User-Agent": "GarenaMSDK/4.0.42(KB2003 ;Android 13;en;HK;app 2.130.1 2019118332;)",
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": `Signature ${sig}`,
          },
          body,
        });
        const text = await r.text();
        return json({
          status: r.status,
          statusText: r.statusText,
          cf_ip_see_headers: Object.fromEntries([...r.headers].filter(([k]) => k.startsWith("cf-") || k === "server")),
          body: text.slice(0, 1000),
        });
      } catch (e) {
        return json({ fetch_error: e.message, cause: e.cause ? String(e.cause) : null }, 502);
      }
    }

    // ── generator ──
    if (url.pathname === "/gen") {
      let count = parseInt(url.searchParams.get("count") || "1", 10);
      if (!Number.isFinite(count) || count < 1) count = 1;
      const activate = url.searchParams.get("activate") === "1";
      let retries = parseInt(url.searchParams.get("retries") || "3", 10);
      if (!Number.isFinite(retries) || retries < 1) retries = 3;
      if (retries > 8) retries = 8;

      const started = Date.now();
      // concurrency: count ke hisaab se, max 10 parallel
      const results = await pool(count, Math.min(10, count), () => generateOne(activate, retries));
      const accounts = results.filter((r) => r.ok).map((r) => r.account);
      const errors = results.filter((r) => !r.ok).map((r) => r.error);

      return json({
        success: accounts.length > 0,
        requested: count,
        generated: accounts.length,
        failed: count - accounts.length,
        activated: activate ? accounts.filter((a) => a.activated).length : undefined,
        took_ms: Date.now() - started,
        errors: errors.length ? errors.slice(0, 5) : undefined,
        accounts,
      });
    }

    return json({ success: false, error: "not found — use /gen?count=1" }, 404);
  },
};
