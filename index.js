import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient } from "mongodb";

dotenv.config();

const PORT = process.env.PORT || 5000;
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/foodzen";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:3000";

const app = express();

app.use(cors({ origin: CORS_ORIGIN }));
app.use(express.json());

/** @type {import("mongodb").Db | null} */
let db = null;

async function connectDB() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db();
  console.log("Connected to MongoDB");
  return client;
}

// --- Health ---

app.get("/api/health", (_req, res) => {
  if (!db) {
    return res.status(503).json({ error: "Database not connected" });
  }
  res.json({ data: { status: "ok" } });
});

async function start() {
  try {
    await connectDB();
    app.listen(PORT, () => {
      console.log(`FoodZen API running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("Failed to start server:", err.message);
    process.exit(1);
  }
}

start();
