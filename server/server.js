import "dotenv/config";
import express from "express";
import pool from "./db.js";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
app.use(express.json());
const result = await pool.query("SELECT NOW()");
console.log(result.rows[0]);

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

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});
