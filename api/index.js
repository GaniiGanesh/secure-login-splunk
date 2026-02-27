import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import fetch from "node-fetch";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;

// In-memory users (demo only)
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
   REGISTER ROUTE
========================= */

app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email & password required" });
  }

  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({
    email,
    password: hashedPassword
  });

  res.json({ message: "User registered successfully" });
});

/* =========================
   LOGIN ROUTE
========================= */

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);

  if (!user) {
    return res.status(401).json({ message: "User not found" });
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {

    // 🔥 Send failed login event to Splunk
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
   START SERVER
========================= */

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});