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
const fs = require("fs");

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
    cookie: { httpOnly: true, sameSite: "lax" },
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

/* ================= GLOBAL LOCALS (สำคัญมาก) ================= */
app.use(async (req, res, next) => {
  try {
    const rows = await all(`SELECT key, value FROM site_settings`);
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
const mdToHtml = (md) => marked.parse(md || "");
const requireAdmin = (req, res, next) =>
  req.session?.isAdmin ? next() : res.redirect("/admin/login");

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
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      created_at TEXT,
      updated_at TEXT
    )
  `);

  const a = await get(`SELECT COUNT(*) c FROM admin_users`);
  if (a.c === 0) {
    await run(
      `INSERT INTO admin_users VALUES (NULL,?,?,?,?)`,
      [
        process.env.ADMIN_USER || "admin",
        await bcrypt.hash(process.env.ADMIN_PASS || "admin1234", 12),
        nowISO(),
        nowISO(),
      ]
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
  const posts = await all(
    `SELECT * FROM posts WHERE is_published=1 ORDER BY created_at DESC LIMIT 5`
  );
  res.render("index", { posts });
});

/* ================= Articles List ================= */
app.get("/articles", async (req, res) => {
  const posts = await all(`
    SELECT id, title, slug, created_at
    FROM posts
    WHERE is_published=1 AND type='article'
    ORDER BY created_at DESC
  `);

  res.render("list", {
    posts,
    pageTitle: "บทความทั้งหมด",
  });
});

/* ================= Single Article ================= */
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


// helper แสดง list ตาม type
async function renderList(req, res, type, pageTitle) {
  const posts = await all(
    `
    SELECT title, slug, content_html, created_at
    FROM posts
    WHERE is_published=1 AND type=?
    ORDER BY datetime(created_at) DESC
    `,
    [type]
  );

  res.render("list", {
    pageTitle,
    posts,
  });
}

// ===== list pages =====
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

// ===== article detail =====
app.get("/article/:slug", async (req, res) => {
  const post = await get(
    `
    SELECT *
    FROM posts
    WHERE slug=? AND is_published=1
    `,
    [req.params.slug]
  );

  if (!post) {
    return res.status(404).send("ไม่พบบทความ");
  }

  res.render("article", {
    pageTitle: post.title,
    post,
  });
});


/* ================= Admin ================= */
app.get("/admin/login", (req, res) =>
  res.render("admin_login", { layout: false, error: null })
);

app.post("/admin/login", async (req, res) => {
  const u = await get(`SELECT * FROM admin_users WHERE username=?`, [
    req.body.user,
  ]);

  if (!u || !(await bcrypt.compare(req.body.pass, u.password_hash))) {
    return res.render("admin_login", {
      layout: false,
      error: "Login ไม่ถูกต้อง",
    });
  }

  req.session.isAdmin = true;
  req.session.adminUserId = u.id;
  res.redirect("/admin/posts");
});

app.get("/admin/posts", requireAdmin, async (req, res) => {
  const posts = await all(`SELECT * FROM posts ORDER BY updated_at DESC`);
  res.render("admin_list", { layout: false, posts });
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
  console.log(`✅ Server → http://0.0.0.0:${PORT}`);
});

  })
  .catch((e) => {
    console.error("❌ DB init failed", e);
    process.exit(1);
  });


  