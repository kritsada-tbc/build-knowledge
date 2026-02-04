const path = require("path");
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const morgan = require("morgan");
const dotenv = require("dotenv");
const sqlite3 = require("sqlite3").verbose();
const { marked } = require("marked");
const bcrypt = require("bcrypt");
const expressLayouts = require("express-ejs-layouts");

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT || 3000);

/* ================= Middleware ================= */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use("/public", express.static(path.join(__dirname, "public")));

/* ================= View Engine ================= */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(expressLayouts);
app.set("layout", "layout_public");

/* ================= Database ================= */
const db = new sqlite3.Database(path.join(__dirname, "data.db"));

const all = (sql, p = []) =>
  new Promise((res, rej) =>
    db.all(sql, p, (e, r) => (e ? rej(e) : res(r)))
  );

const get = (sql, p = []) =>
  new Promise((res, rej) =>
    db.get(sql, p, (e, r) => (e ? rej(e) : res(r)))
  );

const run = (sql, p = []) =>
  new Promise((res, rej) =>
    db.run(sql, p, function (e) {
      e ? rej(e) : res(this);
    })
  );

/* ================= Global locals (สำคัญมาก) ================= */
app.use(async (req, res, next) => {
  try {
    const rows = await all(`SELECT key,value FROM site_settings`);
    const site = {};
    rows.forEach(r => site[r.key] = r.value);
    res.locals.site = site;
    res.locals.pageTitle = site.site_name || "เว็บไซต์";
  } catch {
    res.locals.site = {};
    res.locals.pageTitle = "เว็บไซต์";
  }
  next();
});

/* ================= Init DB ================= */
async function initDb() {
  await run(`
    CREATE TABLE IF NOT EXISTS site_settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);

  const s = await get(`SELECT COUNT(*) c FROM site_settings`);
  if (s.c === 0) {
    await run(
      `INSERT INTO site_settings VALUES (?,?)`,
      ["site_name", "ศูนย์ความรู้วัสดุก่อสร้าง"]
    );
  }

  await run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      slug TEXT UNIQUE,
      content_md TEXT,
      content_html TEXT,
      type TEXT,
      is_published INTEGER,
      created_at TEXT
    )
  `);
}

/* ================= Public Routes ================= */

// หน้าแรก
app.get("/", async (req, res) => {
  const posts = await all(`
    SELECT title,slug,created_at
    FROM posts
    WHERE is_published=1
    ORDER BY created_at DESC
    LIMIT 5
  `);
  res.render("index", { posts });
});

// list กลาง (ใช้ร่วมกันทุกหมวด)
async function renderList(req, res, type, title) {
  const posts = await all(
    `
    SELECT title,slug,created_at
    FROM posts
    WHERE is_published=1 AND type=?
    ORDER BY created_at DESC
    `,
    [type]
  );

  res.render("list", {
    posts,
    pageTitle: title,
  });
}

app.get("/articles", (req, res) =>
  renderList(req, res, "article", "บทความ")
);

app.get("/materials", (req, res) =>
  renderList(req, res, "material", "วัสดุก่อสร้าง")
);

app.get("/tools", (req, res) =>
  renderList(req, res, "tool", "เครื่องมือ")
);

app.get("/dealers", (req, res) =>
  renderList(req, res, "dealer", "แหล่งซื้อ")
);

// บทความเดี่ยว
app.get("/article/:slug", async (req, res) => {
  const post = await get(
    `SELECT * FROM posts WHERE slug=? AND is_published=1`,
    [req.params.slug]
  );

  if (!post) return res.status(404).send("ไม่พบบทความ");

  res.render("article", {
    post,
    pageTitle: post.title,
  });
});

/* ================= Error ================= */
app.use((req, res) => {
  res.status(404).send("404 Not Found");
});

/* ================= Start ================= */
initDb().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`✅ Server running on port ${PORT}`);
  });
});
