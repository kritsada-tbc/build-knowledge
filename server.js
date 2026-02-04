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
const PORT = process.env.PORT || 3000;

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
  new Promise((res, rej) =>
    db.run(sql, p, function (e) {
      e ? rej(e) : res(this);
    })
  );

const get = (sql, p = []) =>
  new Promise((res, rej) =>
    db.get(sql, p, (e, r) => (e ? rej(e) : res(r)))
  );

const all = (sql, p = []) =>
  new Promise((res, rej) =>
    db.all(sql, p, (e, r) => (e ? rej(e) : res(r)))
  );

/* ================= GLOBAL LOCALS ================= */
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

const requireAdmin = (req, res, next) =>
  req.session?.isAdmin ? next() : res.redirect("/admin/login");

/* ================= Init DB ================= */
async function initDb() {
  await run(`
    CREATE TABLE IF NOT EXISTS site_settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      password_hash TEXT,
      created_at TEXT,
      updated_at TEXT
    )
  `);

  const admin = await get(`SELECT COUNT(*) c FROM admin_users`);
  if (admin.c === 0) {
    await run(
      `INSERT INTO admin_users VALUES (NULL,?,?,?,?)`,
      ["admin", await bcrypt.hash("admin1234", 10), nowISO(), nowISO()]
    );
  }

  await run(`
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      slug TEXT UNIQUE,
      content_html TEXT,
      type TEXT,
      is_published INTEGER,
      created_at TEXT
    )
  `);
}

/* ================= Public ================= */
app.get("/", async (req, res) => {
  const posts = await all(`
    SELECT * FROM posts
    WHERE is_published=1
    ORDER BY created_at DESC
    LIMIT 5
  `);
  res.render("index", { posts });
});

function renderList(type, title) {
  return async (req, res) => {
    const posts = await all(
      `SELECT title,slug,created_at FROM posts WHERE is_published=1 AND type=?`,
      [type]
    );
    res.render("list", { posts, pageTitle: title });
  };
}

app.get("/articles", renderList("article", "บทความ"));
app.get("/materials", renderList("material", "วัสดุ"));
app.get("/tools", renderList("tool", "เครื่องมือ"));
app.get("/dealers", renderList("dealer", "แหล่งซื้อ"));

app.get("/article/:slug", async (req, res) => {
  const post = await get(
    `SELECT * FROM posts WHERE slug=? AND is_published=1`,
    [req.params.slug]
  );
  if (!post) return res.status(404).send("ไม่พบบทความ");
  res.render("article", { post, pageTitle: post.title });
});

/* ================= Admin ================= */
app.get("/admin/login", (req, res) =>
  res.render("admin_login", { layout: false, error: null })
);

app.post("/admin/login", async (req, res) => {
  const u = await get(`SELECT * FROM admin_users WHERE username=?`, [req.body.user]);
  if (!u || !(await bcrypt.compare(req.body.pass, u.password_hash))) {
    return res.render("admin_login", { layout: false, error: "Login ผิด" });
  }
  req.session.isAdmin = true;
  res.redirect("/admin/posts");
});

app.get("/admin/posts", requireAdmin, async (req, res) => {
  const type = req.query.type || "article";

  const posts = await all(
    `SELECT * FROM posts WHERE type=? ORDER BY updated_at DESC`,
    [type]
  );

  res.render("admin_list", {
    layout: false,
    posts,
    type, // ⭐ สำคัญมาก
  });
});

// ===== Admin: New Post =====
app.get("/admin/posts/new", requireAdmin, async (req, res) => {
  const type = req.query.type || "article";

  res.render("admin_edit", {
    layout: false,
    pageTitle: "เพิ่มบทความ",
    mode: "new",
    type,
    post: {
      id: null,
      title: "",
      slug: "",
      content_md: "",
      content_html: "",
      is_published: 0,
      type,
    },
    error: null,
  });
});

// ===== Admin: Edit Post =====
app.get("/admin/posts/:id/edit", requireAdmin, async (req, res) => {
  const post = await get(`SELECT * FROM posts WHERE id=?`, [req.params.id]);
  if (!post) return res.status(404).send("ไม่พบโพสต์");

  res.render("admin_edit", {
    layout: false,
    pageTitle: "แก้ไขบทความ",
    mode: "edit",
    type: post.type,
    post,
    error: null,
  });
});

// ===== Admin: Save Post =====
app.post("/admin/posts/save", requireAdmin, async (req, res) => {
  const {
    id,
    title,
    content_md,
    type,
    is_published
  } = req.body;

  const slug = title
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^\u0E00-\u0E7Fa-z0-9\-]/g, "");

  const html = mdToHtml(content_md);
  const now = nowISO();

  if (id) {
    await run(
      `UPDATE posts SET title=?, slug=?, content_md=?, content_html=?, is_published=?, updated_at=? WHERE id=?`,
      [title, slug, content_md, html, is_published ? 1 : 0, now, id]
    );
  } else {
    await run(
      `INSERT INTO posts (title, slug, content_md, content_html, type, is_published, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?)`,
      [title, slug, content_md, html, type, is_published ? 1 : 0, now, now]
    );
  }

  res.redirect("/admin/posts");
});



/* ================= Error ================= */
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send("Server error");
});

/* ================= Start ================= */
initDb().then(() => {
  app.listen(3000, "127.0.0.1", () => {
    console.log("✅ Server running on 127.0.0.1:3000");
  });
});
