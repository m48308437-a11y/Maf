# MFA Anime — مای‌فیوریت‌انیمه

سایت فارسی معرفی، جستجو و مدیریت انیمه‌ها با:

* Node.js
* Express
* SQLite
* HTML / CSS / JavaScript
* سیستم ثبت‌نام و ورود
* پنل مدیریت
* مدیریت انیمه‌ها
* مدیریت نظرات
* جستجو و فیلتر

## ساختار پروژه

```text
MFA-anime/
├── package.json
├── server.js
├── index.html
├── search.html
├── anime-detail.html
├── admin.html
└── README.md
```

## نصب

ابتدا Node.js نسخه LTS را نصب کنید.

سپس داخل پوشه پروژه اجرا کنید:

```bash
npm install
```

## اجرا

```bash
npm start
```

بعد مرورگر را باز کنید:

```text
http://localhost:3000
```

## حساب مدیر اولیه

نام کاربری:

```text
admin
```

رمز عبور:

```text
admin123
```

## حساب کاربر نمونه

نام کاربری:

```text
mfauser
```

رمز عبور:

```text
user123
```

## صفحات

صفحه اصلی:

```text
/
```

جستجو:

```text
/search.html
```

جزئیات انیمه:

```text
/anime-detail.html?id=1
```

پنل مدیریت:

```text
/admin.html
```

## API

ورود:

```text
POST /api/login
```

ثبت‌نام:

```text
POST /api/register
```

دریافت انیمه‌ها:

```text
GET /api/anime
```

دریافت یک انیمه:

```text
GET /api/anime/:id
```

افزودن انیمه:

```text
POST /api/anime
```

ویرایش انیمه:

```text
PUT /api/anime/:id
```

حذف انیمه:

```text
DELETE /api/anime/:id
```

ثبت نظر:

```text
POST /api/anime/:id/comments
```

نظرات در انتظار تأیید:

```text
GET /api/comments/pending
```

## نکته امنیتی

قبل از استفاده عمومی، رمز پیش‌فرض مدیر و مقدار `JWT_SECRET` را تغییر دهید.

برای محیط Production همچنین بهتر است دیتابیس SQLite روی فضای ذخیره‌سازی دائمی قرار بگیرد یا به PostgreSQL منتقل شود.
