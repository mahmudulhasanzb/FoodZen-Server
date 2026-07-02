import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ObjectId } from "mongodb";

dotenv.config();

const PORT = process.env.PORT || 5000;
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/foodzen";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:3000";
const BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";

const app = express();

app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
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

// --- Auth Middleware ---

const VALID_ROLES = ["admin", "manager", "server", "kitchen"];

/**
 * Verify Better Auth session by calling the session endpoint on the client.
 * Attaches req.user (Better Auth user) and req.staff (staff record with role).
 */
async function requireAuth(req, res, next) {
  try {
    // Forward cookies to Better Auth session endpoint
    const sessionRes = await fetch(
      `${BETTER_AUTH_URL}/api/auth/get-session`,
      {
        headers: {
          cookie: req.headers.cookie || "",
        },
      }
    );

    if (!sessionRes.ok) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const sessionData = await sessionRes.json();

    if (!sessionData?.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    req.user = sessionData.user;

    // Look up staff record
    const staff = await db.collection("staff").findOne({
      userId: sessionData.user.id,
      active: true,
    });

    if (!staff) {
      return res.status(403).json({ error: "No active staff record" });
    }

    req.staff = staff;
    next();
  } catch (err) {
    console.error("Auth middleware error:", err.message);
    return res.status(401).json({ error: "Authentication failed" });
  }
}

/**
 * Role-based access guard. Use after requireAuth.
 * requireRole("admin", "manager") — allows only admin or manager.
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.staff || !roles.includes(req.staff.role)) {
      return res
        .status(403)
        .json({ error: "Insufficient permissions" });
    }
    next();
  };
}

// --- Staff API ---

// GET /api/staff — list all staff (admin only)
app.get("/api/staff", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const staff = await db
      .collection("staff")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();
    res.json({ data: staff });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch staff" });
  }
});

// GET /api/staff/me — get current user's staff record
app.get("/api/staff/me", requireAuth, async (req, res) => {
  res.json({ data: req.staff });
});

// POST /api/staff — create staff record (admin only)
app.post(
  "/api/staff",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { userId, name, role } = req.body;

      if (!userId || !name || !role) {
        return res
          .status(400)
          .json({ error: "userId, name, and role are required" });
      }

      if (!VALID_ROLES.includes(role)) {
        return res.status(400).json({
          error: `Invalid role. Must be one of: ${VALID_ROLES.join(", ")}`,
        });
      }

      // Check duplicate
      const existing = await db
        .collection("staff")
        .findOne({ userId });
      if (existing) {
        return res
          .status(409)
          .json({ error: "Staff record already exists for this user" });
      }

      const doc = {
        userId,
        name,
        role,
        active: true,
        createdAt: new Date(),
      };

      const result = await db.collection("staff").insertOne(doc);
      res
        .status(201)
        .json({ data: { ...doc, _id: result.insertedId } });
    } catch (err) {
      res.status(500).json({ error: "Failed to create staff" });
    }
  }
);

// PATCH /api/staff/:id — update staff (admin only)
app.patch(
  "/api/staff/:id",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const updates = {};

      if (req.body.name) updates.name = req.body.name;
      if (req.body.role) {
        if (!VALID_ROLES.includes(req.body.role)) {
          return res.status(400).json({
            error: `Invalid role. Must be one of: ${VALID_ROLES.join(", ")}`,
          });
        }
        updates.role = req.body.role;
      }
      if (typeof req.body.active === "boolean") {
        updates.active = req.body.active;
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: "No valid fields to update" });
      }

      const result = await db
        .collection("staff")
        .findOneAndUpdate(
          { _id: new ObjectId(id) },
          { $set: updates },
          { returnDocument: "after" }
        );

      if (!result) {
        return res.status(404).json({ error: "Staff not found" });
      }

      res.json({ data: result });
    } catch (err) {
      res.status(500).json({ error: "Failed to update staff" });
    }
  }
);

// --- Menu API ---

// GET /api/menu — public, available items only
app.get("/api/menu", async (req, res) => {
  try {
    const filter = { available: { $ne: false } };
    if (req.query.category) {
      filter.category = req.query.category;
    }
    const items = await db
      .collection("menu_items")
      .find(filter)
      .sort({ category: 1, name: 1 })
      .toArray();
    res.json({ data: items });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch menu" });
  }
});

// GET /api/menu/all — protected, ALL items including unavailable (for dashboard)
app.get(
  "/api/menu/all",
  requireAuth,
  requireRole("admin", "manager"),
  async (req, res) => {
    try {
      const items = await db
        .collection("menu_items")
        .find({})
        .sort({ category: 1, name: 1 })
        .toArray();
      res.json({ data: items });
    } catch (err) {
      res.status(500).json({ error: "Failed to fetch menu items" });
    }
  }
);

// GET /api/menu/:id — public, single item (MUST be after /all)
app.get("/api/menu/:id", async (req, res) => {
  try {
    const item = await db
      .collection("menu_items")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!item) {
      return res.status(404).json({ error: "Menu item not found" });
    }
    res.json({ data: item });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch menu item" });
  }
});

// POST /api/menu — create menu item (manager/admin)
app.post(
  "/api/menu",
  requireAuth,
  requireRole("admin", "manager"),
  async (req, res) => {
    try {
      const { name, price, category, description, imageUrl } = req.body;

      if (!name || price == null || !category) {
        return res
          .status(400)
          .json({ error: "name, price, and category are required" });
      }

      if (typeof price !== "number" || price < 0) {
        return res
          .status(400)
          .json({ error: "price must be a non-negative number" });
      }

      const doc = {
        name: name.trim(),
        price,
        category: category.trim(),
        description: description?.trim() || "",
        imageUrl: imageUrl?.trim() || "",
        available: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const result = await db.collection("menu_items").insertOne(doc);
      res.status(201).json({ data: { ...doc, _id: result.insertedId } });
    } catch (err) {
      res.status(500).json({ error: "Failed to create menu item" });
    }
  }
);

// PATCH /api/menu/:id — update menu item (manager/admin)
app.patch(
  "/api/menu/:id",
  requireAuth,
  requireRole("admin", "manager"),
  async (req, res) => {
    try {
      const updates = {};
      const allowed = [
        "name",
        "price",
        "category",
        "description",
        "imageUrl",
        "available",
      ];

      for (const key of allowed) {
        if (req.body[key] !== undefined) {
          updates[key] = req.body[key];
        }
      }

      if (updates.name) updates.name = updates.name.trim();
      if (updates.category) updates.category = updates.category.trim();
      if (updates.description)
        updates.description = updates.description.trim();
      if (updates.imageUrl) updates.imageUrl = updates.imageUrl.trim();

      if (
        updates.price !== undefined &&
        (typeof updates.price !== "number" || updates.price < 0)
      ) {
        return res
          .status(400)
          .json({ error: "price must be a non-negative number" });
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: "No valid fields to update" });
      }

      updates.updatedAt = new Date();

      const result = await db
        .collection("menu_items")
        .findOneAndUpdate(
          { _id: new ObjectId(req.params.id) },
          { $set: updates },
          { returnDocument: "after" }
        );

      if (!result) {
        return res.status(404).json({ error: "Menu item not found" });
      }

      res.json({ data: result });
    } catch (err) {
      res.status(500).json({ error: "Failed to update menu item" });
    }
  }
);

// DELETE /api/menu/:id — delete menu item (manager/admin)
app.delete(
  "/api/menu/:id",
  requireAuth,
  requireRole("admin", "manager"),
  async (req, res) => {
    try {
      const result = await db
        .collection("menu_items")
        .deleteOne({ _id: new ObjectId(req.params.id) });

      if (result.deletedCount === 0) {
        return res.status(404).json({ error: "Menu item not found" });
      }

      res.json({ data: { deleted: true } });
    } catch (err) {
      res.status(500).json({ error: "Failed to delete menu item" });
    }
  }
);

// --- Seed Admin ---

async function seedAdmin() {
  const staffCount = await db.collection("staff").countDocuments();
  if (staffCount === 0) {
    console.log(
      "No staff found. Create an admin user via Better Auth signup, then add a staff record."
    );
    console.log(
      'Hint: POST /api/auth/sign-up/email on client, then manually insert staff doc with role "admin".'
    );
  }
}

// --- Start ---

async function start() {
  try {
    await connectDB();
    await seedAdmin();
    app.listen(PORT, () => {
      console.log(`FoodZen API running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("Failed to start server:", err.message);
    process.exit(1);
  }
}

start();

