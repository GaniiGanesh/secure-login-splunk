import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import fetch from "node-fetch";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
app.use(express.json());

// Fix for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static frontend
app.use(express.static(path.join(__dirname, "../public")));

// In-memory storage (demo only)
let users = [];

/* =========================
   SPLUNK LOG FUNCTION
========================= */
async function sendToSplunk(eventData) {
  try {
    const response = await fetch(process.env.SPLUNK_URL, {
      method: "POST",
      headers: {
        "Authorization": `Splunk ${process.env.SPLUNK_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        event: eventData,
        sourcetype: "login_app"
      })
    });

    const result = await response.json();
    console.log("Splunk response:", result);

  } catch (error) {
    console.error("Splunk error:", error.message);
  }
}

/* =========================
   REGISTER
========================= */
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email & password required" });
  }

  const existing = users.find(u => u.email === email);
  if (existing) {
    return res.status(400).json({ message: "User already exists" });
  }

  const hashed = await bcrypt.hash(password, 10);

  users.push({
    email,
    password: hashed
  });

  res.json({ message: "User registered successfully" });
});

/* =========================
   LOGIN
========================= */
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);

  if (!user) {
    return res.status(401).json({ message: "User not found" });
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    await sendToSplunk({
      type: "failed_login",
      email,
      ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
      user_agent: req.headers["user-agent"],
      timestamp: new Date().toISOString()
    });

    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign({ email }, "supersecret", { expiresIn: "1h" });

  res.json({ message: "Login successful", token });
});

/* =========================
   ROOT ROUTE (IMPORTANT FOR VERCEL)
========================= */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

/* =========================
   LOCAL ONLY (NOT VERCEL)
========================= */
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Local server running on http://localhost:${PORT}`);
  });
}

/* =========================
   EXPORT FOR VERCEL
========================= */
export default app;
