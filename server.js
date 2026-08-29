const express = require("express");

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_SECRET";

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not configured.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({
  extended: true,
  limit: "10mb"
}));

app.use(express.static(__dirname));

/* =========================
   DATABASE
========================= */

const ALLOWED_STATUS = ["در حال پخش", "پایان یافته", "به‌زودی"];
const ALLOWED_AGE_RATING = ["G", "PG", "PG-13", "R", "+18"];

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS anime (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      jp_title TEXT DEFAULT '',
      year TEXT DEFAULT '',
      studio TEXT DEFAULT '',
      country TEXT DEFAULT '',
      genres TEXT DEFAULT '',
      status TEXT DEFAULT 'در حال پخش',
      age_rating TEXT DEFAULT '',
      score NUMERIC(3,1) DEFAULT 0,
      synopsis TEXT DEFAULT '',
      poster TEXT DEFAULT '',
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      anime_id INTEGER NOT NULL REFERENCES anime(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  /* migration safety-net: add new columns if the anime table
     already existed before this update */
  await pool.query(`
    ALTER TABLE anime ADD COLUMN IF NOT EXISTS country TEXT DEFAULT '';
    ALTER TABLE anime ADD COLUMN IF NOT EXISTS age_rating TEXT DEFAULT '';
  `);

  const admin = await pool.query(
    "SELECT id FROM users WHERE username = $1",
    ["admin"]
  );

  if (admin.rowCount === 0) {
    const password = await bcrypt.hash("admin123", 10);

    await pool.query(
      `INSERT INTO users
       (username, password, role)
       VALUES ($1, $2, $3)`,
      ["admin", password, "admin"]
    );
  }

  const demoUser = await pool.query(
    "SELECT id FROM users WHERE username = $1",
    ["mfauser"]
  );

  if (demoUser.rowCount === 0) {
    const password = await bcrypt.hash("user123", 10);

    await pool.query(
      `INSERT INTO users
       (username, password, role)
       VALUES ($1, $2, $3)`,
      ["mfauser", password, "user"]
    );
  }

  console.log("PostgreSQL database ready.");
}

/* =========================
   AUTH
========================= */

function authRequired(req, res, next) {
  try {
    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "احراز هویت لازم است"
      });
    }

    const token = header.slice(7);

    req.user = jwt.verify(
      token,
      JWT_SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      error: "توکن نامعتبر یا منقضی شده است"
    });
  }
}

function adminRequired(req, res, next) {
  if (
    !req.user ||
    req.user.role !== "admin"
  ) {
    return res.status(403).json({
      error: "دسترسی مدیر لازم است"
    });
  }

  next();
}

/* =========================
   REGISTER
========================= */

app.post(
  "/api/register",
  async (req, res) => {
    try {
      const username =
        String(req.body.username || "").trim();

      const password =
        String(req.body.password || "");

      if (
        !username ||
        password.length < 6
      ) {
        return res.status(400).json({
          error:
            "نام کاربری و رمز عبور معتبر وارد کنید"
        });
      }

      const exists = await pool.query(
        "SELECT id FROM users WHERE username = $1",
        [username]
      );

      if (exists.rowCount > 0) {
        return res.status(409).json({
          error:
            "این نام کاربری قبلاً ثبت شده است"
        });
      }

      const hashed =
        await bcrypt.hash(password, 10);

      const result = await pool.query(
        `INSERT INTO users
         (username, password, role)
         VALUES ($1, $2, 'user')
         RETURNING id, username, role`,
        [username, hashed]
      );

      res.status(201).json({
        success: true,
        user: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "خطا در ثبت‌نام"
      });
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const username =
        String(req.body.username || "").trim();

      const password =
        String(req.body.password || "");

      const result = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );

      if (result.rowCount === 0) {
        return res.status(401).json({
          error:
            "نام کاربری یا رمز عبور اشتباه است"
        });
      }

      const user = result.rows[0];

      const valid =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "نام کاربری یا رمز عبور اشتباه است"
        });
      }

      const token =
        jwt.sign(
          {
            id: user.id,
            username: user.username,
            role: user.role
          },
          JWT_SECRET,
          { expiresIn: "7d" }
        );

      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "خطا در ورود"
      });
    }
  }
);

/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/me",
  authRequired,
  (req, res) => {
    res.json({
      success: true,
      user: req.user
    });
  }
);

/* =========================
   USERS - ADMIN
========================= */

app.get(
  "/api/admin/users",
  authRequired,
  adminRequired,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          username,
          role,
          created_at
        FROM users
        ORDER BY id DESC
      `);

      res.json({
        success: true,
        data: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در دریافت کاربران"
      });
    }
  }
);

/* تغییر نقش */

app.patch(
  "/api/admin/users/:id/role",
  authRequired,
  adminRequired,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const role =
        String(req.body.role || "").trim();

      if (
        !["user", "admin"].includes(role)
      ) {
        return res.status(400).json({
          error: "نقش نامعتبر است"
        });
      }

      if (
        Number(req.user.id) === id &&
        role !== "admin"
      ) {
        return res.status(400).json({
          error:
            "نمی‌توانی ادمینی خودت را حذف کنی"
        });
      }

      const result = await pool.query(
        `UPDATE users
         SET role = $1
         WHERE id = $2
         RETURNING id, username, role, created_at`,
        [role, id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "کاربر پیدا نشد"
        });
      }

      res.json({
        success: true,
        message:
          role === "admin"
            ? "کاربر ادمین شد"
            : "نقش کاربر تغییر کرد",
        user: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در تغییر نقش"
      });
    }
  }
);

/* ادمین کردن با username */

app.post(
  "/api/admin/promote",
  authRequired,
  adminRequired,
  async (req, res) => {
    try {
      const username =
        String(
          req.body.username || ""
        ).trim();

      if (!username) {
        return res.status(400).json({
          error:
            "نام کاربری را وارد کنید"
        });
      }

      const result = await pool.query(
        `UPDATE users
         SET role = 'admin'
         WHERE username = $1
         RETURNING id, username, role`,
        [username]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "کاربری با این نام پیدا نشد"
        });
      }

      res.json({
        success: true,
        message:
          `کاربر ${username} اکنون ادمین است`,
        user: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در ادمین کردن کاربر"
      });
    }
  }
);

/* =========================
   ANIME LIST
========================= */

app.get(
  "/api/anime",
  async (req, res) => {
    try {
      const q =
        String(req.query.q || "").trim();

      const genre =
        String(req.query.genre || "").trim();

      const status =
        String(req.query.status || "").trim();

      const country =
        String(req.query.country || "").trim();

      const minScore =
        req.query.minScore !== undefined
          ? Number(req.query.minScore)
          : null;

      const sort =
        String(
          req.query.sort || "newest"
        );

      const values = [];
      const conditions = [];

      if (q) {
        values.push(`%${q}%`);

        conditions.push(`
          (
            title ILIKE $${values.length}
            OR jp_title ILIKE $${values.length}
            OR studio ILIKE $${values.length}
            OR genres ILIKE $${values.length}
          )
        `);
      }

      if (genre) {
        values.push(`%${genre}%`);

        conditions.push(
          `genres ILIKE $${values.length}`
        );
      }

      if (status) {
        values.push(status);

        conditions.push(
          `status = $${values.length}`
        );
      }

      if (country) {
        values.push(`%${country}%`);

        conditions.push(
          `country ILIKE $${values.length}`
        );
      }

      if (
        minScore !== null &&
        Number.isFinite(minScore)
      ) {
        values.push(minScore);

        conditions.push(
          `score >= $${values.length}`
        );
      }

      let sql =
        "SELECT * FROM anime";

      if (conditions.length) {
        sql +=
          " WHERE " +
          conditions.join(" AND ");
      }

      if (sort === "score") {
        sql +=
          " ORDER BY score DESC, id DESC";
      } else if (sort === "alpha") {
        sql +=
          " ORDER BY title ASC";
      } else {
        sql +=
          " ORDER BY id DESC";
      }

      const result =
        await pool.query(
          sql,
          values
        );

      res.json({
        success: true,
        data: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در دریافت انیمه‌ها"
      });
    }
  }
);

/* =========================
   ANIME DETAIL
========================= */

app.get(
  "/api/anime/:id",
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const animeResult =
        await pool.query(
          "SELECT * FROM anime WHERE id = $1",
          [id]
        );

      if (animeResult.rowCount === 0) {
        return res.status(404).json({
          error:
            "انیمه پیدا نشد"
        });
      }

      const commentsResult =
        await pool.query(
          `
          SELECT
            comments.id,
            comments.text,
            comments.created_at,
            users.username
          FROM comments
          JOIN users
            ON users.id = comments.user_id
          WHERE comments.anime_id = $1
            AND comments.status = 'approved'
          ORDER BY comments.id DESC
          `,
          [id]
        );

      res.json({
        success: true,
        anime: animeResult.rows[0],
        comments: commentsResult.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در دریافت اطلاعات"
      });
    }
  }
);

/* =========================
   ADD ANIME
========================= */

app.post(
  "/api/anime",
  authRequired,
  adminRequired,
  async (req, res) => {
    try {
      const {
        title,
        jp_title = "",
        year = "",
        studio = "",
        country = "",
        genres = "",
        status = "در حال پخش",
        age_rating = "",
        score = 0,
        synopsis = "",
        poster = ""
      } = req.body;

      if (
        !title ||
        !String(title).trim()
      ) {
        return res.status(400).json({
          error:
            "عنوان فارسی الزامی است"
        });
      }

      if (status && !ALLOWED_STATUS.includes(status)) {
        return res.status(400).json({
          error: "وضعیت نامعتبر است"
        });
      }

      if (age_rating && !ALLOWED_AGE_RATING.includes(age_rating)) {
        return res.status(400).json({
          error: "رده سنی نامعتبر است"
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO anime
          (
            title,
            jp_title,
            year,
            studio,
            country,
            genres,
            status,
            age_rating,
            score,
            synopsis,
            poster
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
          RETURNING *
          `,
          [
            String(title).trim(),
            jp_title,
            year,
            studio,
            country,
            genres,
            status,
            age_rating,
            Number(score) || 0,
            synopsis,
            poster
          ]
        );

      res.status(201).json({
        success: true,
        anime: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در افزودن انیمه"
      });
    }
  }
);

/* =========================
   EDIT ANIME
========================= */

app.put(
  "/api/anime/:id",
  authRequired,
  adminRequired,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const current =
        await pool.query(
          "SELECT * FROM anime WHERE id = $1",
          [id]
        );

      if (current.rowCount === 0) {
        return res.status(404).json({
          error:
            "انیمه پیدا نشد"
        });
      }

      const old =
        current.rows[0];

      if (
        req.body.status &&
        !ALLOWED_STATUS.includes(req.body.status)
      ) {
        return res.status(400).json({
          error: "وضعیت نامعتبر است"
        });
      }

      if (
        req.body.age_rating &&
        !ALLOWED_AGE_RATING.includes(req.body.age_rating)
      ) {
        return res.status(400).json({
          error: "رده سنی نامعتبر است"
        });
      }

      const updated = {
        title:
          req.body.title ?? old.title,

        jp_title:
          req.body.jp_title ?? old.jp_title,

        year:
          req.body.year ?? old.year,

        studio:
          req.body.studio ?? old.studio,

        country:
          req.body.country ?? old.country,

        genres:
          req.body.genres ?? old.genres,

        status:
          req.body.status ?? old.status,

        age_rating:
          req.body.age_rating ?? old.age_rating,

        score:
          req.body.score ?? old.score,

        synopsis:
          req.body.synopsis ?? old.synopsis,

        poster:
          req.body.poster ?? old.poster
      };

      const result =
        await pool.query(
          `
          UPDATE anime
          SET
            title = $1,
            jp_title = $2,
            year = $3,
            studio = $4,
            country = $5,
            genres = $6,
            status = $7,
            age_rating = $8,
            score = $9,
            synopsis = $10,
            poster = $11
          WHERE id = $12
          RETURNING *
          `,
          [
            updated.title,
            updated.jp_title,
            updated.year,
            updated.studio,
            updated.country,
            updated.genres,
            updated.status,
            updated.age_rating,
            Number(updated.score) || 0,
            updated.synopsis,
            updated.poster,
            id
          ]
        );

      res.json({
        success: true,
        anime: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در ویرایش انیمه"
      });
    }
  }
);

/* =========================
   DELETE ANIME
========================= */

app.delete(
  "/api/anime/:id",
  authRequired,
  adminRequired,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const result =
        await pool.query(
          "DELETE FROM anime WHERE id = $1 RETURNING id",
          [id]
        );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "انیمه پیدا نشد"
        });
      }

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در حذف انیمه"
      });
    }
  }
);

/* =========================
   COMMENTS
========================= */

app.post(
  "/api/anime/:id/comments",
  authRequired,
  async (req, res) => {
    try {
      const animeId =
        Number(req.params.id);

      const text =
        String(
          req.body.text || ""
        ).trim();

      if (!text) {
        return res.status(400).json({
          error:
            "متن نظر خالی است"
        });
      }

      const anime =
        await pool.query(
          "SELECT id FROM anime WHERE id = $1",
          [animeId]
        );

      if (anime.rowCount === 0) {
        return res.status(404).json({
          error:
            "انیمه پیدا نشد"
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO comments
          (anime_id, user_id, text, status)
          VALUES ($1, $2, $3, 'pending')
          RETURNING id
          `,
          [
            animeId,
            req.user.id,
            text
          ]
        );

      res.status(201).json({
        success: true,
        message:
          "نظر شما ثبت شد و پس از تأیید نمایش داده می‌شود",
        id: result.rows[0].id
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در ثبت نظر"
      });
    }
  }
);

app.get(
  "/api/comments/pending",
  authRequired,
  adminRequired,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            comments.id,
            comments.text,
            comments.status,
            comments.created_at,
            users.username,
            anime.title AS anime_title
          FROM comments
          JOIN users
            ON users.id = comments.user_id
          JOIN anime
            ON anime.id = comments.anime_id
          WHERE comments.status = 'pending'
          ORDER BY comments.id DESC
        `);

      res.json({
        success: true,
        data: result.rows
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در دریافت نظرات"
      });
    }
  }
);

app.patch(
  "/api/comments/:id",
  authRequired,
  adminRequired,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const status =
        String(
          req.body.status || ""
        );

      if (
        ![
          "pending",
          "approved",
          "rejected"
        ].includes(status)
      ) {
        return res.status(400).json({
          error:
            "وضعیت نامعتبر است"
        });
      }

      const result =
        await pool.query(
          `
          UPDATE comments
          SET status = $1
          WHERE id = $2
          RETURNING id, status
          `,
          [status, id]
        );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "نظر پیدا نشد"
        });
      }

      res.json({
        success: true,
        comment: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در تغییر وضعیت نظر"
      });
    }
  }
);

app.delete(
  "/api/comments/:id",
  authRequired,
  adminRequired,
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const result =
        await pool.query(
          "DELETE FROM comments WHERE id = $1 RETURNING id",
          [id]
        );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "نظر پیدا نشد"
        });
      }

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در حذف نظر"
      });
    }
  }
);

/* =========================
   ADMIN STATS
========================= */

app.get(
  "/api/admin/stats",
  authRequired,
  adminRequired,
  async (req, res) => {
    try {
      const anime =
        await pool.query(
          "SELECT COUNT(*) AS count FROM anime"
        );

      const users =
        await pool.query(
          "SELECT COUNT(*) AS count FROM users"
        );

      const pending =
        await pool.query(
          `
          SELECT COUNT(*) AS count
          FROM comments
          WHERE status = 'pending'
          `
        );

      res.json({
        success: true,
        stats: {
          animeCount:
            Number(anime.rows[0].count),

          usersCount:
            Number(users.rows[0].count),

          pendingComments:
            Number(pending.rows[0].count)
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در دریافت آمار"
      });
    }
  }
);

/* =========================
   HEALTH CHECK
========================= */

app.get(
  "/api/health",
  async (req, res) => {
    try {
      await pool.query("SELECT 1");

      res.json({
        success: true,
        database: "postgresql",
        status: "ok"
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        database: "postgresql",
        status: "error"
      });
    }
  }
);

/* =========================
   HOME
========================= */

app.get("/", (req, res) => {
  res.sendFile(
    __dirname + "/index.html"
  );
});

/* =========================
   START
========================= */

async function startServer() {
  try {
    await initDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `MFA server running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "Failed to start server:",
      error
    );

    process.exit(1);
  }
}

startServer();
