```js
const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "mfa-change-this-secret";

const dbPath =
  process.env.DB_PATH || path.join(__dirname, "mfa.db");

const db = new Database(dbPath);

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({
  extended: true,
  limit: "10mb"
}));

app.use(express.static(__dirname));

/* =========================
   DATABASE
========================= */

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS anime (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    jp_title TEXT DEFAULT '',
    year TEXT DEFAULT '',
    studio TEXT DEFAULT '',
    genres TEXT DEFAULT '',
    status TEXT DEFAULT 'در حال پخش',
    score REAL DEFAULT 0,
    synopsis TEXT DEFAULT '',
    poster TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    anime_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (anime_id) REFERENCES anime(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

/* =========================
   DEFAULT USERS
========================= */

const adminPassword =
  bcrypt.hashSync("admin123", 10);

const sampleUserPassword =
  bcrypt.hashSync("user123", 10);

const adminExists = db
  .prepare(
    "SELECT id FROM users WHERE username = ?"
  )
  .get("admin");

if (!adminExists) {
  db.prepare(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
  ).run(
    "admin",
    adminPassword,
    "admin"
  );
}

const sampleUserExists = db
  .prepare(
    "SELECT id FROM users WHERE username = ?"
  )
  .get("mfauser");

if (!sampleUserExists) {
  db.prepare(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
  ).run(
    "mfauser",
    sampleUserPassword,
    "user"
  );
}

/* =========================
   HELPERS
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

    const token =
      header.substring(7);

    const decoded =
      jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
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
   AUTH
========================= */

app.post(
  "/api/register",
  async (req, res) => {
    try {
      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );

      if (
        !username ||
        password.length < 6
      ) {
        return res.status(400).json({
          error:
            "نام کاربری و رمز عبور معتبر وارد کنید"
        });
      }

      const exists =
        db.prepare(
          "SELECT id FROM users WHERE username = ?"
        ).get(username);

      if (exists) {
        return res.status(409).json({
          error:
            "این نام کاربری قبلاً ثبت شده است"
        });
      }

      const hashed =
        await bcrypt.hash(
          password,
          10
        );

      const result =
        db.prepare(
          `INSERT INTO users
          (username, password, role)
          VALUES (?, ?, 'user')`
        ).run(
          username,
          hashed
        );

      return res.json({
        success: true,
        user: {
          id: result.lastInsertRowid,
          username,
          role: "user"
        }
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "خطا در ثبت‌نام"
      });
    }
  }
);

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const username =
        String(
          req.body.username || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );

      const user =
        db.prepare(
          "SELECT * FROM users WHERE username = ?"
        ).get(username);

      if (!user) {
        return res.status(401).json({
          error:
            "نام کاربری یا رمز عبور اشتباه است"
        });
      }

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
          {
            expiresIn: "7d"
          }
        );

      return res.json({
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

      return res.status(500).json({
        error:
          "خطا در ورود"
      });
    }
  }
);

app.get(
  "/api/me",
  authRequired,
  (req, res) => {
    res.json({
      user: req.user
    });
  }
);

/* =========================
   USERS
========================= */

/*
  فقط مدیر فعلی می‌تواند
  نقش یک کاربر را تغییر دهد.
*/

app.get(
  "/api/admin/users",
  authRequired,
  adminRequired,
  (req, res) => {
    try {
      const users =
        db.prepare(`
          SELECT
            id,
            username,
            role,
            created_at
          FROM users
          ORDER BY id DESC
        `).all();

      res.json({
        success: true,
        data: users
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

app.patch(
  "/api/admin/users/:id/role",
  authRequired,
  adminRequired,
  (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const role =
        String(
          req.body.role || ""
        ).trim();

      if (
        !["user", "admin"].includes(role)
      ) {
        return res.status(400).json({
          error:
            "نقش نامعتبر است"
        });
      }

      const targetUser =
        db.prepare(
          "SELECT * FROM users WHERE id = ?"
        ).get(id);

      if (!targetUser) {
        return res.status(404).json({
          error:
            "کاربر پیدا نشد"
        });
      }

      /*
        جلوگیری از حذف سطح ادمینی
        خود ادمین فعلی.
      */

      if (
        Number(req.user.id) === id &&
        role !== "admin"
      ) {
        return res.status(400).json({
          error:
            "نمی‌توانی نقش خودت را از ادمین به کاربر تغییر دهی"
        });
      }

      db.prepare(
        "UPDATE users SET role = ? WHERE id = ?"
      ).run(
        role,
        id
      );

      const updated =
        db.prepare(
          "SELECT id, username, role, created_at FROM users WHERE id = ?"
        ).get(id);

      res.json({
        success: true,
        message:
          role === "admin"
            ? "کاربر با موفقیت ادمین شد"
            : "نقش کاربر تغییر کرد",
        user: updated
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در تغییر نقش کاربر"
      });
    }
  }
);

/*
  مسیر آماده برای ادمین کردن
  مستقیم با username.
*/

app.post(
  "/api/admin/promote",
  authRequired,
  adminRequired,
  (req, res) => {
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

      const targetUser =
        db.prepare(
          "SELECT id, username, role FROM users WHERE username = ?"
        ).get(username);

      if (!targetUser) {
        return res.status(404).json({
          error:
            "کاربر با این نام کاربری پیدا نشد"
        });
      }

      db.prepare(
        "UPDATE users SET role = 'admin' WHERE id = ?"
      ).run(targetUser.id);

      const updated =
        db.prepare(
          "SELECT id, username, role FROM users WHERE id = ?"
        ).get(targetUser.id);

      res.json({
        success: true,
        message:
          `کاربر ${username} اکنون ادمین است`,
        user: updated
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
   ANIME
========================= */

app.get(
  "/api/anime",
  (req, res) => {
    try {
      const {
        q = "",
        genre = "",
        status = "",
        minScore = "",
        sort = "newest"
      } = req.query;

      let sql =
        "SELECT * FROM anime WHERE 1=1";

      const params = {};

      if (q.trim()) {
        sql += `
          AND (
            title LIKE @q
            OR jp_title LIKE @q
            OR studio LIKE @q
            OR genres LIKE @q
          )
        `;

        params.q =
          `%${q.trim()}%`;
      }

      if (genre.trim()) {
        sql +=
          " AND genres LIKE @genre";

        params.genre =
          `%${genre.trim()}%`;
      }

      if (status.trim()) {
        sql +=
          " AND status = @status";

        params.status =
          status.trim();
      }

      if (minScore !== "") {
        sql +=
          " AND score >= @minScore";

        params.minScore =
          Number(minScore);
      }

      if (sort === "score") {
        sql +=
          " ORDER BY score DESC";
      } else if (sort === "alpha") {
        sql +=
          " ORDER BY title ASC";
      } else {
        sql +=
          " ORDER BY id DESC";
      }

      const rows =
        db.prepare(sql).all(params);

      res.json({
        success: true,
        data: rows
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

app.get(
  "/api/anime/:id",
  (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const anime =
        db.prepare(
          "SELECT * FROM anime WHERE id = ?"
        ).get(id);

      if (!anime) {
        return res.status(404).json({
          error:
            "انیمه پیدا نشد"
        });
      }

      const comments =
        db.prepare(`
          SELECT
            comments.id,
            comments.text,
            comments.created_at,
            users.username
          FROM comments
          JOIN users
            ON users.id = comments.user_id
          WHERE comments.anime_id = ?
            AND comments.status = 'approved'
          ORDER BY comments.id DESC
        `).all(id);

      res.json({
        success: true,
        anime,
        comments
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در دریافت اطلاعات انیمه"
      });
    }
  }
);

app.post(
  "/api/anime",
  authRequired,
  adminRequired,
  (req, res) => {
    try {
      const {
        title,
        jp_title = "",
        year = "",
        studio = "",
        genres = "",
        status = "در حال پخش",
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

      const result =
        db.prepare(`
          INSERT INTO anime
          (
            title,
            jp_title,
            year,
            studio,
            genres,
            status,
            score,
            synopsis,
            poster
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          String(title).trim(),
          jp_title,
          year,
          studio,
          genres,
          status,
          Number(score) || 0,
          synopsis,
          poster
        );

      const anime =
        db.prepare(
          "SELECT * FROM anime WHERE id = ?"
        ).get(
          result.lastInsertRowid
        );

      res.status(201).json({
        success: true,
        anime
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

app.put(
  "/api/anime/:id",
  authRequired,
  adminRequired,
  (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const current =
        db.prepare(
          "SELECT * FROM anime WHERE id = ?"
        ).get(id);

      if (!current) {
        return res.status(404).json({
          error:
            "انیمه پیدا نشد"
        });
      }

      const updated = {
        title:
          req.body.title ??
          current.title,

        jp_title:
          req.body.jp_title ??
          current.jp_title,

        year:
          req.body.year ??
          current.year,

        studio:
          req.body.studio ??
          current.studio,

        genres:
          req.body.genres ??
          current.genres,

        status:
          req.body.status ??
          current.status,

        score:
          req.body.score ??
          current.score,

        synopsis:
          req.body.synopsis ??
          current.synopsis,

        poster:
          req.body.poster ??
          current.poster
      };

      db.prepare(`
        UPDATE anime
        SET
          title = ?,
          jp_title = ?,
          year = ?,
          studio = ?,
          genres = ?,
          status = ?,
          score = ?,
          synopsis = ?,
          poster = ?
        WHERE id = ?
      `).run(
        updated.title,
        updated.jp_title,
        updated.year,
        updated.studio,
        updated.genres,
        updated.status,
        Number(updated.score) || 0,
        updated.synopsis,
        updated.poster,
        id
      );

      const anime =
        db.prepare(
          "SELECT * FROM anime WHERE id = ?"
        ).get(id);

      res.json({
        success: true,
        anime
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

app.delete(
  "/api/anime/:id",
  authRequired,
  adminRequired,
  (req, res) => {
    try {
      const id =
        Number(req.params.id);

      db.prepare(
        "DELETE FROM comments WHERE anime_id = ?"
      ).run(id);

      const result =
        db.prepare(
          "DELETE FROM anime WHERE id = ?"
        ).run(id);

      if (result.changes === 0) {
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
  (req, res) => {
    try {
      const animeId =
        Number(req.params.id);

      const text =
        String(
          req.body.text || ""
        ).trim();

      const anime =
        db.prepare(
          "SELECT id FROM anime WHERE id = ?"
        ).get(animeId);

      if (!anime) {
        return res.status(404).json({
          error:
            "انیمه پیدا نشد"
        });
      }

      if (!text) {
        return res.status(400).json({
          error:
            "متن نظر خالی است"
        });
      }

      const result =
        db.prepare(`
          INSERT INTO comments
          (anime_id, user_id, text, status)
          VALUES (?, ?, ?, 'pending')
        `).run(
          animeId,
          req.user.id,
          text
        );

      res.status(201).json({
        success: true,
        message:
          "نظر شما ثبت شد و پس از تأیید نمایش داده می‌شود",
        id:
          result.lastInsertRowid
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
  (req, res) => {
    try {
      const comments =
        db.prepare(`
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
        `).all();

      res.json({
        success: true,
        data: comments
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
  (req, res) => {
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
        db.prepare(
          "UPDATE comments SET status = ? WHERE id = ?"
        ).run(
          status,
          id
        );

      if (result.changes === 0) {
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
          "خطا در تغییر وضعیت نظر"
      });
    }
  }
);

app.delete(
  "/api/comments/:id",
  authRequired,
  adminRequired,
  (req, res) => {
    try {
      const id =
        Number(req.params.id);

      const result =
        db.prepare(
          "DELETE FROM comments WHERE id = ?"
        ).run(id);

      if (result.changes === 0) {
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
  (req, res) => {
    try {
      const animeCount =
        db.prepare(
          "SELECT COUNT(*) AS count FROM anime"
        ).get().count;

      const usersCount =
        db.prepare(
          "SELECT COUNT(*) AS count FROM users"
        ).get().count;

      const pendingComments =
        db.prepare(`
          SELECT COUNT(*) AS count
          FROM comments
          WHERE status = 'pending'
        `).get().count;

      res.json({
        success: true,
        stats: {
          animeCount,
          usersCount,
          pendingComments
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
   HOME
========================= */

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

/* =========================
   START
========================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `MFA server running on port ${PORT}`
    );
  }
);
```
