import "dotenv/config";
import express from "express";
import pool from "./db.js";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import bcrypt from "bcrypt";

const pgSessions = connectPgSimple(session);
const app = express();
const port = 3000;
app.set("trust proxy", 1);
app.use(express.json());

app.use(
  session({
    store: new pgSessions({
      pool: pool,
      tableName: "user_sessions",
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  }),
);

app.use(express.json());
const result = await pool.query("SELECT NOW()");
console.log(result.rows[0]);

app.get("/test-session", (req, res) => {
  req.session.views = (req.session.views || 0) + 1;
  res.json({ views: req.session.views });
});

app.post("/api/auth/register", async (req, res) => {
  console.log("NEW REGISTRATION ROUTE HIT");
  const { username, email, password } = req.body;

  try {
    if (!username || !email || !password) {
      return res.status(400).json({
        message: "Please provide a username, email, and password",
      });
    }

    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email],
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        message: "Email is already registered",
      });
    }
    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      "INSERT INTO users (username, email, password_hash) VALUES($1, $2, $3) RETURNING id, username, email, created_at",
      [username, email, hashedPassword],
    );
    return res.status(201).json({
      message: "Account created successfully",
      user: result.rows[0],
    });
  } catch (err) {
    // console.error(err);
    return res.status(500).json({
      message: "Something went wrong",
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Please fill out all required fields",
      });
    }
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length === 0) {
      return res.status(401).json({
        status: "fail",
        message: "Invalid email or password",
      });
    }

    const user = result.rows[0];

    const comparedPass = await bcrypt.compare(password, user.password_hash);

    if (!comparedPass) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "something went wrong" });
      }
      req.session.userId = user.id;
      return res.status(200).json({
        status: "success",
        message: "Login successfull",
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
        },
      });
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      message: "Something went wrong",
    });
  }
});

app.get("/api/auth/me", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      message: "Not logged in",
    });
  }

  try {
    const result = await pool.query(
      "SELECT id, username, email FROM users WHERE id = $1",
      [req.session.userId],
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Not logged in" });
    }

    return res.status(200).json({ user: result.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Something went wrong" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Something went wrong" });
    }

    res.clearCookie("connect.sid");
    return res.status(200).json({ message: "Logged out" });
  });
});

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});
