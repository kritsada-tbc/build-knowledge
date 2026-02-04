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

const run = (sql, p = []) =>
  new Promise((res, rej) => db.run(sql, p, e => e ? rej(e) : res()));

const get = (sql, p = []) =>
  new Promise((res, rej) => db.get(sql, p, (e, r) => e ? rej(e) : res(r)));

const all = (sql, p = []) =>
  new Promise((res, rej) => db.all(sql, p, (e, r) => e ? rej(e) : res(r)));

/* ================= Global locals ================= */
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

/* ================= Helpers ================= */
const nowISO = () => new Date().toISOString();
const mdToHtml = md => marked.parse(md || "");

/* ================= Init DB ================= */
async function initDb() {
  await run(`
    CREATE TABLE IF NOT EXISTS site_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
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
      created_at TEXT,
      updated_at TEXT
    )
  `);
}

/* ================= Public ================= */

// หน้าแรก
app.get("/", async (req, res) => {
  const posts = await all(`
    SELECT title, slug, created_at
    FROM posts
    WHERE is_published=1
    ORDER BY created_at DESC
    LIMIT 5
  `);

  res.render("index", { posts });
});

// helper list
async function renderList(res, type, title) {
  const posts = await all(
    `SELECT title, slug, created_at
     FROM posts
     WHERE is_published=1 AND type=?
     ORDER BY created_at DESC`,
    [type]
  );

  res.render("list", {
    pageTitle: title,
    posts,
  });
}

// list pages
app.get("/articles", (_, res) => renderList(res, "article", "บทความ"));
app.get("/materials", (_, res) => renderList(res, "material", "วัสดุก่อสร้าง"));
app.get("/tools",     (_, res) => renderList(res, "tool", "เครื่องมือ"));
app.get("/dealers",   (_, res) => renderList(res, "dealer", "แหล่งซื้อ"));

// article detail
app.get("/article/:slug", async (req, res) => {
  const post = await get(
    `SELECT * FROM posts WHERE slug=? AND is_published=1`,
    [req.params.slug]
  );

  if (!post) return res.status(404).send("ไม่พบบทความ");

  res.render("article", {
    pageTitle: post.title,
    post,
  });
});

/* ================= Error ================= */
app.use((err, req, res, next) => {
  console.error("❌ SERVER ERROR:", err);
  res.status(500).send("Server error");
});

/* ================= Start ================= */
initDb()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`✅ Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error("❌ DB init failed", err);
    process.exit(1);
  });
