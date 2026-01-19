require("dotenv").config({ quiet: true });

const express = require("express");
const scratchRoutes = require("./routes/scratchRoutes");

const app = express();

const allowedOrigins = new Set([
  "https://jockey-scratch-card-admin.vercel.app",
  "https://jockey-scratch-card-website.vercel.app",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:4173",
  "http://127.0.0.1:4173"
]);

const isDev = process.env.NODE_ENV !== "production";

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allow = isDev || !origin || allowedOrigins.has(origin);

  if (allow) {
    res.setHeader("Access-Control-Allow-Origin", origin || "*");
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json());

app.get("/", (req, res) => {
  res.status(200).send("Backend running");
});

app.use("/api", scratchRoutes);

module.exports = app;
