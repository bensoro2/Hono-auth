import { serve } from "@hono/node-server";
import { Hono } from "hono";
import mysql from "mysql2/promise";
import type { RowDataPacket } from "mysql2/promise";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

// Interface definitions
interface User extends RowDataPacket {
  id: number;
  username: string;
  password: string;
  email: string;
}

interface RegisterRequest {
  username: string;
  password: string;
  email: string;
}

interface LoginRequest {
  username: string;
  password: string;
}

const app = new Hono();

const dbConfig = {
  host: "localhost",
  user: "root",
  password: "bb12345677",
  database: "auth_db",
};

// Register Endpoint
app.post("/register", async (c) => {
  const { username, password, email } = await c.req.json<RegisterRequest>();
  const hashedPassword = await bcrypt.hash(password, 10);

  const connection = await mysql.createConnection(dbConfig);
  try {
    await connection.execute(
      "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
      [username, hashedPassword, email]
    );
    return c.json({ message: "User registered successfully" });
  } catch (error) {
    return c.json({ message: "Registration failed", error }, 500);
  } finally {
    await connection.end();
  }
});

// Login Endpoint
app.post("/login", async (c) => {
  const { username, password } = await c.req.json<LoginRequest>();

  const connection = await mysql.createConnection(dbConfig);
  try {
    const [rows] = await connection.execute<User[]>(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    // Check if user exists
    if (rows.length === 0) {
      return c.json({ message: "User not found" }, 404);
    }

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return c.json({ message: "Invalid password" }, 401);
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      "your_jwt_secret",
      { expiresIn: "1h" }
    );
    return c.json({ token });
  } catch (error) {
    return c.json({ message: "Login failed", error }, 500);
  } finally {
    await connection.end();
  }
});

// Protected Route
app.get("/protected", async (c) => {
  const authHeader = c.req.header("Authorization");
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return c.json({ message: "Token not provided" }, 401);
  }

  try {
    const user = jwt.verify(token, "your_jwt_secret");
    return c.json({ message: "Protected content", user });
  } catch (error) {
    return c.json({ message: "Invalid token" }, 403);
  }
});

// Root Endpoint
app.get("/", (c) => {
  return c.text("Hello Hono!");
});

const port = 3000;
console.log(`Server is running on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});
