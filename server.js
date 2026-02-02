const path = require("path");
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const morgan = require("morgan");
const dotenv = require("dotenv");
const sqlite3 = require("sqlite3").verbose();
const { marked } = require("marked");
const bcrypt = require("bcrypt");
const multer = require("multer");

const expressLayouts = require("express-ejs-layouts");

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

// ===== Middleware =====
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" },
  })
);

app.use(express.static('public'));

app.set("view engine", "ejs");
app.use(expressLayouts);
app.set("layout", "layout_public");
app.set("views", path.join(__dirname, "views"));
app.use("/public", express.static(path.join(__dirname, "public")));
const uploadDir = path.join(__dirname, "public", "uploads");

const fs = require("fs");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const safe = Date.now() + "-" + Math.random().toString(16).slice(2) + ext;
    cb(null, safe);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB
});


// ===== DB =====
const db = new sqlite3.Database(path.join(__dirname, "data.db"));

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

// ===== Helpers =====
function nowISO() {
  return new Date().toISOString();
}

function slugify(input) {
  return String(input || "")
    .trim()
    .toLowerCase()
    .replace(/[\s\_]+/g, "-")
    .replace(/[^\u0E00-\u0E7Fa-z0-9\-]+/g, "")
    .replace(/\-+/g, "-")
    .replace(/^\-|\-$/g, "");
}

function mdToHtml(md) {
  return marked.parse(md || "");
}

function typeLabel(type) {
  return type === "material"
    ? "วัสดุก่อสร้าง"
    : type === "tool"
    ? "เครื่องมือช่าง"
    : type === "dealer"
    ? "ตัวแทนจำหน่าย"
    : "บทความ";
}

function safeType(input) {
  const t = String(input || "article").trim().toLowerCase();
  return ["article", "material", "tool", "dealer"].includes(t) ? t : "article";
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.redirect("/admin/login");
}


app.get("/admin/change-password", requireAdmin, (req, res) => {
  res.render("admin_change_password", {
  layout: false,
  error: null,
  success: null
});

});

app.post("/admin/change-password", requireAdmin, async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;

  if (!oldPassword || !newPassword || !confirmPassword) {
    return res.render("admin_change_password", {
      error: "กรุณากรอกข้อมูลให้ครบ",
      success: null
    });
  }

  if (newPassword !== confirmPassword) {
    return res.render("admin_change_password", {
      error: "รหัสผ่านใหม่ไม่ตรงกัน",
      success: null
    });
  }

  const admin = await get(
    "SELECT id, password_hash FROM admin_users WHERE id = ?",
    [req.session.adminUserId]
  );

  if (!admin) {
    return res.redirect("/admin/login");
  }

  const match = await bcrypt.compare(oldPassword, admin.password_hash);
  if (!match) {
    return res.render("admin_change_password", {
      error: "รหัสผ่านเดิมไม่ถูกต้อง",
      success: null
    });
  }

  const hash = await bcrypt.hash(newPassword, 12);

  await run(
    "UPDATE admin_users SET password_hash=?, updated_at=? WHERE id=?",
    [hash, nowISO(), admin.id]
  );

  // เปลี่ยนรหัสแล้ว logout
  req.session.destroy(() => {
    res.redirect("/admin/login");
  });
});


// ✅ จับ error ของ async routes ไม่ให้ทำ Node ล่ม
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);


// ===== Init / Migrations (ONE PLACE ONLY) =====
async function initDb() {

  // ----- media_files -----
  await run(`
    CREATE TABLE IF NOT EXISTS media_files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      original_name TEXT NOT NULL,
      file_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      url TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

// ----- posts -----
await run(`
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    excerpt TEXT DEFAULT '',
    content_md TEXT NOT NULL,
    content_html TEXT NOT NULL,
    tags TEXT DEFAULT '',
    type TEXT DEFAULT 'article',
    is_published INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);


// migration: add extra fields to media_files (รองรับ DB เก่า)
const mediaCols = await all(`PRAGMA table_info(media_files)`);
const hasAlt = mediaCols.some(c => c.name === "alt_text");

if (!hasAlt) {
  await run(`ALTER TABLE media_files ADD COLUMN alt_text TEXT DEFAULT ''`);
  await run(`ALTER TABLE media_files ADD COLUMN caption TEXT DEFAULT ''`);
  await run(`ALTER TABLE media_files ADD COLUMN usage_count INTEGER DEFAULT 0`);
}


  // migration: add type column to posts (safe)
const postCols = await all(`PRAGMA table_info(posts)`);
if (postCols.length > 0) {
  const hasType = postCols.some(c => c.name === "type");
  if (!hasType) {
    await run(`ALTER TABLE posts ADD COLUMN type TEXT DEFAULT 'article'`);
  }
}


  // ----- admin_users -----
  await run(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);

  // seed admin if empty
  const adminCount = await get(`SELECT COUNT(*) AS c FROM admin_users`);
  if ((adminCount?.c || 0) === 0) {
    const username = process.env.ADMIN_USER || "admin";
    const pass = process.env.ADMIN_PASS || "admin1234";
    const hash = await bcrypt.hash(pass, 12);
    const ts = nowISO();
    await run(
      `INSERT INTO admin_users (username, password_hash, created_at, updated_at) VALUES (?,?,?,?)`,
      [username, hash, ts, ts]
    );
    console.log("✅ Seed admin user created:", username);
  }

  // ----- site_settings (key/value) -----
  // ถ้าเคยมี schema เก่า ให้ reset เฉพาะตารางนี้
  try {
    const sCols = await all(`PRAGMA table_info(site_settings)`);
    const hasKey = sCols.some((c) => c.name === "key");
    const hasValue = sCols.some((c) => c.name === "value");
    if (!hasKey || !hasValue) {
      await run(`DROP TABLE IF EXISTS site_settings`);
      await run(`
        CREATE TABLE site_settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
      `);
    } else {
      await run(`
        CREATE TABLE IF NOT EXISTS site_settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
      `);
    }
  } catch {
    await run(`
      CREATE TABLE IF NOT EXISTS site_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
  }

  // defaults ถ้ายังไม่มี
  const siteAny = await get(`SELECT COUNT(*) AS c FROM site_settings`);
  if ((siteAny?.c || 0) === 0) {
    const defaults = [
      ["site_name", "ศูนย์ความรู้วัสดุก่อสร้าง"],
      ["meta_description", "เว็บให้ความรู้เกี่ยวกับวัสดุก่อสร้าง คู่มือเลือกวัสดุ และเครื่องมือคำนวณ"],
      ["theme_accent", "#4aa3ff"],
      ["theme_accent2", "#7c5cff"],
      ["hero_title", "เว็บให้ความรู้วัสดุก่อสร้าง อ่านง่าย ใช้จริง หน้างานเข้าใจ"],
      ["hero_subtitle", "รวมคำอธิบายวัสดุ ข้อดี-ข้อจำกัด วิธีเลือก และเช็คลิสต์การใช้งาน (ไม่มีการขายสินค้า)"],
    ];
    for (const [k, v] of defaults) {
      await run(`INSERT INTO site_settings (key,value) VALUES (?,?)`, [k, v]);
    }
  }

  // ----- contact_messages -----
  await run(`
    CREATE TABLE IF NOT EXISTS contact_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      contact TEXT DEFAULT '',
      subject TEXT DEFAULT '',
      message TEXT NOT NULL,
      created_at TEXT NOT NULL,
      is_read INTEGER DEFAULT 0
    );
  `);



  // ----- home_sections / home_cards (เผื่อปรับหน้าแรก) -----
  await run(`
    CREATE TABLE IF NOT EXISTS home_sections (
      key TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      is_enabled INTEGER DEFAULT 1,
      sort_order INTEGER DEFAULT 0
    );
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS home_cards (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      section_key TEXT NOT NULL,
      title TEXT NOT NULL,
      subtitle TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      href TEXT DEFAULT '#',
      is_enabled INTEGER DEFAULT 1,
      sort_order INTEGER DEFAULT 0
    );
  `);
}

// ===== Load site_settings into res.locals =====
app.use(async (req, res, next) => {
  try {
    const rows = await all(`SELECT key, value FROM site_settings`);
    const site = {};
    rows.forEach((r) => (site[r.key] = r.value));
    res.locals.site = site;
  } catch {
    res.locals.site = {};
  }
  next();
});

// ===== Public Routes =====
app.get("/", async (req, res) => {
  const latest = async (type) =>
    all(
      `
      SELECT title, slug, excerpt, created_at, type
      FROM posts
      WHERE is_published=1 AND type=?
      ORDER BY datetime(created_at) DESC
      LIMIT 3
    `,
      [type]
    );

  const [articles, materials, tools, dealers] = await Promise.all([
    latest("article"),
    latest("material"),
    latest("tool"),
    latest("dealer"),
  ]);

  res.render("index", {
    pageTitle: res.locals.site?.site_name || "ศูนย์ความรู้วัสดุก่อสร้าง",
    site: res.locals.site || {},
    articles,
    materials,
    tools,
    dealers,
  });
});

async function renderList(req, res, type, pageTitle) {
  const posts = await all(
    `
    SELECT title, slug, excerpt, created_at, type
    FROM posts
    WHERE is_published=1 AND type=?
    ORDER BY datetime(created_at) DESC
    LIMIT 200
  `,
    [type]
  );
  res.render("list", { pageTitle, site: res.locals.site || {}, posts, type });
}

app.get("/articles", (req, res) => renderList(req, res, "article", "บทความทั่วไปเกี่ยวกับงานก่อสร้าง"));
app.get("/materials", (req, res) => renderList(req, res, "material", "หมวดข้อมูลวัสดุก่อสร้าง"));
app.get("/tools", (req, res) => renderList(req, res, "tool", "หมวดข้อมูลอุปกรณ์เครื่องมือช่าง"));
app.get("/dealers", (req, res) => renderList(req, res, "dealer", "หมวดตัวแทนจำหน่าย / แหล่งซื้อสินค้า"));

app.get("/article/:slug", async (req, res) => {
  try {
    const post = await get(
      `
      SELECT id, title, slug, excerpt, content_html, tags, type, created_at, updated_at
      FROM posts
      WHERE slug=? AND is_published=1
    `,
      [req.params.slug]
    );

    if (!post) {
      return res.status(404).send("ไม่พบบทความ");
    }

    // ป้องกัน content_html ว่าง
    post.content_html = post.content_html || "<p>(ไม่มีเนื้อหา)</p>";

    res.render("article", {
      pageTitle: post.title,
      site: res.locals.site || {},
      post
    });

  } catch (err) {
    console.error("❌ ARTICLE ERROR:", err);
    res.status(500).send("เกิดข้อผิดพลาดในการแสดงบทความ");
  }
});

app.get("/contact", (req, res) => {
  res.render("contact", {
    pageTitle: "ติดต่อโฆษณา / ลงบทความ",
    site: res.locals.site || {},
    ok: null,
    error: null,
  });
});

app.post("/contact/send", async (req, res) => {
  const name = String(req.body.name || "").trim();
  const contact = String(req.body.contact || "").trim();
  const subject = String(req.body.subject || "").trim();
  const message = String(req.body.message || "").trim();

  if (!name || !message) {
    return res.status(400).render("contact", {
      pageTitle: "ติดต่อโฆษณา / ลงบทความ",
      site: res.locals.site || {},
      ok: null,
      error: "กรุณากรอกชื่อ และข้อความ",
    });
  }

  await run(
    `
    INSERT INTO contact_messages (name, contact, subject, message, created_at, is_read)
    VALUES (?,?,?,?,?,0)
  `,
    [name, contact, subject, message, nowISO()]
  );

  res.render("contact", {
    pageTitle: "ติดต่อโฆษณา / ลงบทความ",
    site: res.locals.site || {},
    ok: "ส่งข้อความเรียบร้อยแล้ว",
    error: null,
  });
});

// ===== Admin Auth (ใช้ admin_users + bcrypt) =====
app.get("/admin/login", (req, res) => {
  if (req.session && req.session.isAdmin) return res.redirect("/admin/posts?type=article");
  res.render("admin_login", {
  layout: false,
  pageTitle: "Admin Login",
  error: null
});

});

app.post("/admin/login", async (req, res) => {
  const user = String(req.body.user || "").trim();
  const pass = String(req.body.pass || "").trim();

  const row = await get(`SELECT id, username, password_hash FROM admin_users WHERE username=?`, [user]);
  if (!row) {
    return res.status(401).render("admin_login", {
      pageTitle: "Admin Login",
      error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง",
    });
  }

  const ok = await bcrypt.compare(pass, row.password_hash);
  if (!ok) {
    return res.status(401).render("admin_login", {
      pageTitle: "Admin Login",
      error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง",
    });
  }

  req.session.isAdmin = true;
  req.session.adminUserId = row.id;
  req.session.save(() => res.redirect("/admin/posts?type=article"));
});

app.post("/admin/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/admin/login"));
});

// ===== Admin: Posts =====
app.get("/admin/posts", requireAdmin, async (req, res) => {
  const type = safeType(req.query.type || "article");

  const posts = await all(
    `
    SELECT id, title, slug, type, is_published, created_at, updated_at
    FROM posts
    WHERE type=?
    ORDER BY datetime(updated_at) DESC
  `,
    [type]
  );

  res.render("admin_list", {
  layout: false,
  pageTitle: `จัดการ: ${typeLabel(type)}`,
  posts,
  type,
});

});

app.get("/admin/posts/new", requireAdmin, (req, res) => {
  const type = safeType(req.query.type || "article");
  res.render("admin_edit", {
  layout: false,
  pageTitle: `เพิ่ม: ${typeLabel(type)}`,
  mode: "new",
  type,
  post: {
  id: null,
  title: "",
  slug: "",
  excerpt: "",
  content_md: "",
  tags: "",
  is_published: 0,
  type
},

  error: null,
});

});

app.get("/admin/posts/:id/edit", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const post = await get(
    `
    SELECT id, title, slug, excerpt, content_md, tags, is_published, type
    FROM posts WHERE id=?
  `,
    [id]
  );

  if (!post) return res.status(404).send("ไม่พบรายการ");
  res.render("admin_edit", {
  layout: false,
  pageTitle: `แก้ไข: ${typeLabel(post.type)}`,
  mode: "edit",
  type: post.type || "article",
  post,
  error: null,
});

});

app.post("/admin/posts/save", requireAdmin, async (req, res) => {
  const id = req.body.id ? Number(req.body.id) : null;
  const type = safeType(req.body.type || "article");

  const title = String(req.body.title || "").trim();
  const excerpt = String(req.body.excerpt || "").trim();
  const content_md = String(req.body.content_md || "").trim();
  const tags = String(req.body.tags || "").trim();
  const is_published = req.body.is_published ? 1 : 0;

  let slug = String(req.body.slug || "").trim();
  slug = slug ? slugify(slug) : slugify(title);

  if (!title || !content_md) {
    return res.status(400).render("admin_edit", {
      pageTitle: id ? `แก้ไข: ${typeLabel(type)}` : `เพิ่ม: ${typeLabel(type)}`,
      mode: id ? "edit" : "new",
      type,
      post: { id, title, slug, excerpt, content_md, tags, is_published, type },
      error: "กรุณากรอก Title และ Content",
    });
  }

  const content_html = mdToHtml(content_md);
  const ts = nowISO();

  try {
    if (id) {
      await run(
        `
        UPDATE posts
        SET title=?, slug=?, excerpt=?, content_md=?, content_html=?, tags=?, type=?, is_published=?, updated_at=?
        WHERE id=?
      `,
        [title, slug, excerpt, content_md, content_html, tags, type, is_published, ts, id]
      );
    } else {
      await run(
        `
        INSERT INTO posts (title, slug, excerpt, content_md, content_html, tags, type, is_published, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
      `,
        [title, slug, excerpt, content_md, content_html, tags, type, is_published, ts, ts]
      );
    }

    res.redirect(`/admin/posts?type=${type}`);
  } catch (e) {
    return res.status(400).render("admin_edit", {
      pageTitle: id ? `แก้ไข: ${typeLabel(type)}` : `เพิ่ม: ${typeLabel(type)}`,
      mode: id ? "edit" : "new",
      type,
      post: { id, title, slug, excerpt, content_md, tags, is_published, type },
      error: "บันทึกไม่สำเร็จ: slug อาจซ้ำ หรือข้อมูลไม่ถูกต้อง",
    });
  }
});

app.post("/admin/posts/:id/delete", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const row = await get(`SELECT type FROM posts WHERE id=?`, [id]);
  const type = safeType(row?.type || "article");
  await run(`DELETE FROM posts WHERE id=?`, [id]);
  res.redirect(`/admin/posts?type=${type}`);
});

// ===== Admin: Messages =====
app.get("/admin/messages", requireAdmin, async (req, res) => {
  const msgs = await all(`
    SELECT id, name, contact, subject, message, created_at, is_read
    FROM contact_messages
    ORDER BY datetime(created_at) DESC
    LIMIT 200
  `);

  res.render("admin_messages", {
    layout: false,
    pageTitle: "ข้อความติดต่อ",
    msgs
  });
});


app.post("/admin/messages/:id/read", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  await run(`UPDATE contact_messages SET is_read=1 WHERE id=?`, [id]);
  res.redirect("/admin/messages");
});

app.post("/admin/messages/:id/delete", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  await run(`DELETE FROM contact_messages WHERE id=?`, [id]);
  res.redirect("/admin/messages");
});

// ===== Admin: UI Settings =====
app.get("/admin/ui", requireAdmin, asyncHandler(async (req, res) => {
  const rows = await all(`SELECT key, value FROM site_settings`);
  const site = {};
  rows.forEach(r => site[r.key] = r.value);
  res.render("admin_ui", {
  layout: false,
  pageTitle: "ตั้งค่า UI เว็บไซต์",
  site,
  error: null
});

}));

app.post("/admin/ui/save", requireAdmin, asyncHandler(async (req, res) => {
  const keys = [
    "site_name","meta_description",
    "hero_title","hero_subtitle",
    "theme_bg","theme_card","theme_text","theme_muted","theme_line",
    "theme_accent","theme_accent2",
    "hero_image_url","logo_text","site_tagline"
  ];

  for (const k of keys) {
    // ถ้า form ไม่มีช่องนั้น ให้ข้าม ไม่ต้องเขียนค่าว่างทับ
    if (!(k in req.body)) continue;
    const v = String(req.body[k] || "").trim();
    await run(`INSERT OR REPLACE INTO site_settings (key,value) VALUES (?,?)`, [k, v]);
  }

  res.redirect("/admin/ui");
}));

// ===== Admin: Media Library =====
app.get("/admin/media", requireAdmin, async (req, res) => {
  const files = await all(`
    SELECT id, original_name, url, size, created_at
    FROM media_files
    ORDER BY datetime(created_at) DESC
  `);

  res.render("admin_media", {
  layout: false,
  pageTitle: "Media Library",
  files
});

});

// ===== Admin: Media JSON (for insert image modal) =====
app.get("/admin/media/json", requireAdmin, async (req, res) => {
  const files = await all(`
    SELECT id, original_name, url
    FROM media_files
    ORDER BY datetime(created_at) DESC
  `);
  res.json(files);
});

app.post(
  "/admin/media/upload",
  requireAdmin,
  upload.single("file"),
  async (req, res) => {

    // 1. ต้องเช็คก่อน
    if (!req.file) {
      return res.redirect("/admin/media");
    }

    // 2. เช็คชนิดไฟล์
    if (!req.file.mimetype.startsWith("image/")) {
      return res.status(400).send("Only image files are allowed");
    }

    const url = "/public/uploads/" + req.file.filename;

    await run(
      `
      INSERT INTO media_files
      (original_name, file_name, mime_type, size, url, created_at)
      VALUES (?,?,?,?,?,?)
      `,
      [
        req.file.originalname,
        req.file.filename,
        req.file.mimetype,
        req.file.size,
        url,
        nowISO(),
      ]
    );

    res.redirect("/admin/media");
  }
);


app.post("/admin/media/:id/delete", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);

  const file = await get(
    `SELECT file_name FROM media_files WHERE id=?`,
    [id]
  );

  if (file) {
    const filePath = path.join(uploadDir, file.file_name);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }

  await run(`DELETE FROM media_files WHERE id=?`, [id]);
  res.redirect("/admin/media");
});




// ===== Admin: Account (เปลี่ยน ID/Password) =====
app.get("/admin/account", requireAdmin, async (req, res) => {
  const me = await get(`SELECT id, username FROM admin_users WHERE id=?`, [req.session.adminUserId]);
  res.render("admin_account", {
  layout: false,
  pageTitle: "ตั้งค่าบัญชีแอดมิน",
  me,
  error: null,
  ok: null
});

});

app.post("/admin/account/save", requireAdmin, async (req, res) => {
  const newUser = String(req.body.username || "").trim();
  const newPass = String(req.body.new_password || "").trim();
  const newPass2 = String(req.body.new_password2 || "").trim();

  const me = await get(`SELECT id, username FROM admin_users WHERE id=?`, [req.session.adminUserId]);
  if (!me) return res.redirect("/admin/login");

  if (!newUser) {
    return res.status(400).render("admin_account", { pageTitle: "ตั้งค่าบัญชีแอดมิน", me, error: "กรุณากรอก username", ok: null });
  }

  if ((newPass || newPass2) && newPass !== newPass2) {
    return res.status(400).render("admin_account", { pageTitle: "ตั้งค่าบัญชีแอดมิน", me, error: "รหัสผ่านใหม่ไม่ตรงกัน", ok: null });
  }

  try {
    // update username
    await run(`UPDATE admin_users SET username=?, updated_at=? WHERE id=?`, [newUser, nowISO(), me.id]);

    // update password if provided
    if (newPass) {
      const hash = await bcrypt.hash(newPass, 12);
      await run(`UPDATE admin_users SET password_hash=?, updated_at=? WHERE id=?`, [hash, nowISO(), me.id]);
    }

    const me2 = await get(`SELECT id, username FROM admin_users WHERE id=?`, [me.id]);
    return res.render("admin_account", { pageTitle: "ตั้งค่าบัญชีแอดมิน", me: me2, error: null, ok: "บันทึกเรียบร้อย" });
  } catch (e) {
    return res.status(400).render("admin_account", { pageTitle: "ตั้งค่าบัญชีแอดมิน", me, error: "บันทึกไม่สำเร็จ (username อาจซ้ำ)", ok: null });
  }
});

// ✅ Error handler (ถ้าเกิดพัง จะไม่ล่ม แต่จะโชว์ 500 และพิมพ์ error ใน terminal)
app.use((err, req, res, next) => {
  console.error("❌ SERVER ERROR:", err);
  res.status(500).send("Server error. ดูรายละเอียดในหน้าต่างที่รัน npm run dev");
});


// ===== 404 =====
app.use((req, res) => res.status(404).send("404 Not Found"));

// ===== Start (SAFE MODE) =====
initDb()
  .then(() => {
    const server = app.listen(PORT, () => {
      console.log(`✅ Server running → http://localhost:${PORT}`);
    });

    server.on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        console.error(`❌ PORT ${PORT} ถูกใช้งานอยู่แล้ว`);
        console.error("👉 วิธีแก้:");
        console.error("1) ปิด Node ตัวเก่าที่รันอยู่");
        console.error("2) หรือรันด้วยคำสั่ง:");
        console.error("   set PORT=3001 && npm run dev");
        process.exit(1);
      } else {
        console.error("❌ Server error:", err);
        process.exit(1);
      }
    });
  })
  .catch((e) => {
    console.error("❌ initDb failed:", e);
    process.exit(1);
  });

