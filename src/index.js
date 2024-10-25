import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

// Load environment variables from .env file
dotenv.config();

// Initialize Prisma Client
const prisma = new PrismaClient();
const app = new Hono();

// Middleware สำหรับตรวจสอบ JWT
const jwtVerify = (c, next) => {
  const authHeader = c.req.header("Authorization");
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return c.json({ message: "Token not provided" }, 401);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return c.json({ message: "Invalid token" }, 403);
    }
    c.req.user = user; // เก็บข้อมูลผู้ใช้ใน req
    next(); // เรียกใช้งาน middleware ถัดไป
  });
};

// Register Endpoint
app.post("/register", async (c) => {
  const { username, password, email } = await c.req.json();
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
        email,
      },
    });
    return c.json({ message: "User registered successfully" });
  } catch (error) {
    return c.json({ message: "Registration failed", error }, 500);
  }
});

// Login Endpoint
app.post("/login", async (c) => {
  const { username, password } = await c.req.json();

  try {
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) {
      return c.json({ message: "User not found" }, 404);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return c.json({ message: "Invalid password" }, 401);
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    return c.json({ token });
  } catch (error) {
    return c.json({ message: "Login failed", error }, 500);
  }
});

// Protected Route
app.get("/protected", jwtVerify, (c) => {
  return c.json({ message: "Protected content", user: c.req.user });
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
