import "dotenv/config";
import express from "express";
import mysql from "mysql2/promise";
import session from "express-session";
import bcrypt from "bcrypt";
import { GoogleGenAI } from "@google/genai";

const apiKey = process.env.API_KEY;
const app = express();

/**
 * Google Gemini Client
 * @type {GoogleGenAI}
 */
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

/**
 * Database connection pool
 * @type {mysql.Pool}
 */
const pool = mysql.createPool({
  host: process.env.HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DATABASE,
  connectionLimit: 10,
  waitForConnections: true,
});

app.set("trust proxy", 1);
app.use(
  session({
    secret: "mealmatch secret",
    resave: false,
    saveUninitialized: true,
  })
);


app.use((req, res, next) => {
  res.locals.isAuthenticated = !!req.session.isAuthenticated;
  res.locals.userName = req.session.userName || null;
  res.locals.isAdmin = !!req.session.isAdmin;
  next();
});

/**
 * Require user authentication
 * @function requireLogin
 */
function requireLogin(req, res, next) {
  if (req.session.isAuthenticated) return next();
  return res.redirect("/login");
}

/**
 * Require admin privileges
 * @function requireAdmin
 */
function requireAdmin(req, res, next) {
  if (req.session.isAuthenticated && req.session.isAdmin) return next();
  return res.status(403).send("Access denied.");
}

/**
 * Insert or update a recipe in the foodRecipes table.
 *
 * @async
 * @function upsertFoodRecipe
 * @param {number|string} recipeId - Recipe ID from API.
 * @param {string} title - Name of the recipe.
 */
async function upsertFoodRecipe(recipeId, title) {
  const id = Number(recipeId);

  const ingredients = "Imported from API";
  const instructions = "See external recipe link for details.";
  const isFavorite = 1;

  await pool.query(
    `INSERT INTO foodRecipes (recipeID, title, ingredients, instructions, isFavorite)
     VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       title = VALUES(title),
       ingredients = VALUES(ingredients),
       instructions = VALUES(instructions),
       isFavorite = VALUES(isFavorite)`,
    [id, title, ingredients, instructions, isFavorite]
  );
}

/**
 * Extract or estimate nutritional information for a recipe.
 *
 * @async
 * @function extractNutrition
 * @param {object} recipeData - Raw recipe object (Spoonacular or MealDB).
 * @param {number} servings - Number of servings consumed.
 * @returns {Promise<object>} Nutrition data {calories, protein, fat, carbs}
 */
async function extractNutrition(recipeData, servings = 1) {
  const simplifiedRecipe = {
    title: recipeData.title || recipeData.strMeal || "Unknown Recipe",
    servings: recipeData.servings || 1,
    ingredients: recipeData.extendedIngredients
      ? recipeData.extendedIngredients
          .slice(0, 5)
          .map((i) => `${i.amount} ${i.unit} ${i.name}`)
          .join(", ")
      : "Various ingredients",
  };

  const prompt = `
Estimate nutritional information for this recipe:
Title: ${simplifiedRecipe.title}
Key ingredients: ${simplifiedRecipe.ingredients}
Recipe serves: ${simplifiedRecipe.servings}
User consumed: ${servings} serving(s)

Return ONLY this JSON format:
{"calories": 0, "protein": 0, "fat": 0, "carbs": 0}
`.trim();

  try {
    const result = await ai.models.generateContent({
      model: "gemini-2.5-flash",
      contents: prompt,
    });

    const text = result.response ? result.response.text() : result.text;
    const jsonText = text.replace(/```json\n?|\n?```/g, "").trim();
    return JSON.parse(jsonText);
  } catch {
    const baseCalories = 420 * servings;
    return {
      calories: Math.round(baseCalories),
      protein: Math.round((baseCalories * 0.2) / 4),
      fat: Math.round((baseCalories * 0.3) / 9),
      carbs: Math.round((baseCalories * 0.5) / 4),
    };
  }
}

/* ============================================================
 *                        BASIC ROUTES
 * ============================================================*/


app.get("/", async (req, res) => {
  // Guest: just render with no snapshotTotals (home.ejs will fall back to sample)
  if (!req.session.isAuthenticated) {
    return res.render("home.ejs", { snapshotTotals: null });
  }

  const userId = req.session.userId;

  try {
    const [rows] = await pool.query(
      `SELECT id, recipeID, recipeTitle, calories, protein, carbs, fat, date_logged
         FROM tracker
        WHERE userID = ?
        ORDER BY date_logged DESC`,
      [userId]
    );

    const today = new Date().toISOString().slice(0, 10); 

    const todayRows = rows.filter((r) => {
      const d =
        r.date_logged instanceof Date
          ? r.date_logged.toISOString().slice(0, 10)
          : String(r.date_logged).slice(0, 10);
      return d === today;
    });

    const totals = todayRows.reduce(
      (acc, r) => {
        acc.calories += r.calories || 0;
        acc.protein += Number(r.protein || 0);
        acc.carbs += Number(r.carbs || 0);
        acc.fat += Number(r.fat || 0);
        return acc;
      },
      { calories: 0, protein: 0, carbs: 0, fat: 0 }
    );

    res.render("home.ejs", { snapshotTotals: totals });
  } catch (err) {
    console.error("Home snapshot error:", err);
    // If something fails, fall back to sample values in the view
    res.render("home.ejs", { snapshotTotals: null });
  }
});


/* ============================================================
 *                        ADMIN ROUTES
 * ============================================================*/

/**
 * Admin login page
 */
app.get("/admin", (req, res) => {
  if (req.session.isAuthenticated && req.session.isAdmin) {
    return res.redirect("/admin/dashboard");
  }
  res.render("admin.ejs", { loginError: "" });
});

/**
 * Admin dashboard
 */
app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT userID, username, email, isAdmin FROM usersMM ORDER BY userID"
    );

    const meals = [];
    res.render("adminDashboard.ejs", { users, meals });
  } catch (err) {
    console.error("Admin dashboard error:", err);
    res.status(500).send("Error loading admin dashboard.");
  }
});

/**
 * Create new user (admin-only)
 */
app.post("/admin/users/create", async (req, res) => {
  const { username, email, password, isAdmin } = req.body;

  if (!username || !email || !password) {
    return res.status(400).send("Username, email, and password are required.");
  }

  try {
    const [existing] = await pool.query(
      "SELECT userID FROM usersMM WHERE email = ? OR username = ?",
      [email, username]
    );

    if (existing.length) {
      return res.status(400).send("A user with that email or username already exists.");
    }

    const hash = await bcrypt.hash(password, 10);
    const isAdminFlag = isAdmin ? 1 : 0;

    await pool.query(
      "INSERT INTO usersMM (username, email, password, isAdmin) VALUES (?, ?, ?, ?)",
      [username, email, hash, isAdminFlag]
    );

    res.redirect("/admin/dashboard");
  } catch (err) {
    console.error("Admin create user error:", err);
    res.status(500).send("Error creating user.");
  }
});

/**
 * Delete a user (admin-only)
 */
app.post("/admin/users/:id/delete", requireAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    if (Number(id) === req.session.userId) {
      return res.status(400).send("You cannot delete your own account.");
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // delete child rows first
      await conn.query("DELETE FROM tracker WHERE userID = ?", [id]);
      await conn.query("DELETE FROM userFavorites WHERE userID = ?", [id]);

      // now delete the user
      await conn.query("DELETE FROM usersMM WHERE userID = ?", [id]);

      await conn.commit();
    } catch (txErr) {
      await conn.rollback();
      throw txErr;
    } finally {
      conn.release();
    }

    res.redirect("/admin/dashboard");
  } catch (err) {
    console.error("Admin delete user error:", err);
    res.status(500).send("Error deleting user.");
  }
});

/* ============================================================
 *                        RECIPES ROUTES
 * ============================================================*/

/**
 * Fetch a random recipe from API (falls back to MealDB)
 */
app.get("/recipes/random", async (req, res) => {
  try {
    let response = await fetch(
      `https://api.spoonacular.com/recipes/random?apiKey=${apiKey}`
    );
    let data = await response.json();

    if (data.code === 402 || data.status === "failure") {
      const fallback = await fetch(
        "https://www.themealdb.com/api/json/v1/1/random.php"
      );
      const alt = await fallback.json();
      return res.render("recipesFallback.ejs", { meals: alt.meals || [], keyword: "" });
    }

    res.render("recipes.ejs", { meals: data.recipes || [], keyword: "" });
  } catch (err) {
    console.error("API error:", err);
    res.status(500).send("Error fetching recipes");
  }
});

/**
 * Search recipes by ingredient keyword
 */
app.get("/recipes", async (req, res) => {
  const keyword = (req.query.keyword || "").trim();
  if (!keyword) return res.render("recipes.ejs", { meals: [], keyword: "" });

  try {
    const url = `https://api.spoonacular.com/recipes/findByIngredients?apiKey=${apiKey}&ingredients=${encodeURIComponent(
      keyword
    )}&number=9`;

    let response = await fetch(url);
    let data = await response.json();

    if (data.code === 402 || data.status === "failure") {
      const fallback = await fetch(
        `https://www.themealdb.com/api/json/v1/1/search.php?s=${encodeURIComponent(
          keyword
        )}`
      );
      const alt = await fallback.json();
      return res.render("recipesFallback.ejs", { meals: alt.meals || [], keyword });
    }

    const meals =
      Array.isArray(data)
        ? await Promise.all(
            data.map(async (recipe) => {
              const detail = await fetch(
                `https://api.spoonacular.com/recipes/${recipe.id}/information?apiKey=${apiKey}`
              );
              return detail.json();
            })
          )
        : [];

    res.render("recipes.ejs", { meals, keyword });
  } catch (err) {
    console.error("API error:", err);
    res.status(500).send("Error fetching recipes");
  }
});

/* ============================================================
 *                        AUTH ROUTES
 * ============================================================*/

/**
 * Login page
 */
app.get("/login", async (req, res) => {
  if (req.session.isAuthenticated) return res.redirect("/");
  res.render("login.ejs", { title: "Login", loginError: "" });
});

/**
 * Process login credentials
 */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query("SELECT * FROM usersMM WHERE email = ?", [email]);

    if (!rows.length) {
      return res.render("login.ejs", { title: "Login", loginError: "Invalid email or password." });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.render("login.ejs", { title: "Login", loginError: "Invalid email or password." });
    }

    req.session.isAuthenticated = true;
    req.session.userId = user.userID;
    req.session.userName = user.username;
    req.session.isAdmin = !!user.isAdmin;

    res.redirect("/");
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("Server error during login.");
  }
});

/**
 * Logout user
 */
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

/**
 * Create account page
 */
app.get("/create", async (req, res) => {
  if (req.session.isAuthenticated) return res.redirect("/");
  res.render("create.ejs", { title: "Create Account", registerError: "" });
});

/**
 * Create a new user account
 */
app.post("/create", async (req, res) => {
  const { username, email, password, confirm } = req.body;

  if (!username || !email || !password || password !== confirm) {
    return res.render("create.ejs", {
      title: "Create Account",
      registerError: "Please fill all fields and make sure passwords match.",
    });
  }

  try {
    const [existing] = await pool.query(
      "SELECT * FROM usersMM WHERE email = ? OR username = ?",
      [email, username]
    );

    if (existing.length) {
      return res.render("create.ejs", {
        title: "Create Account",
        registerError: "Email or username already in use.",
      });
    }

    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO usersMM (username, email, password) VALUES (?, ?, ?)",
      [username, email, hash]
    );

    res.redirect("/login");
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).send("Server error during registration.");
  }
});

/* ============================================================
 *                        FAVORITES ROUTES
 * ============================================================*/

/**
 * Favorites page
 */
app.get("/favorites", async (req, res) => {
  const sort = req.query.sort || "name";

  if (!req.session.isAuthenticated) {
    return res.render("favorites.ejs", { favorites: null, sort });
  }

  try {
    const userId = req.session.userId;

    let orderBy = "title";
    let direction = "ASC";

    // for some reason, the sort is implemented correctly but gemini is giving an inconsistent macros from the tracker/ in the favorites
    if (sort === "calories" || sort === "protein") {
      orderBy = sort;
      direction = "DESC";
    }

    const [rows] = await pool.query(
      `SELECT recipeID, title, imageUrl, calories, protein
       FROM userFavorites
       WHERE userID = ?
       ORDER BY ${orderBy} ${direction}, title ASC`,
      [userId]
    );

    res.render("favorites.ejs", { favorites: rows, sort });
  } catch (err) {
    console.error("Favorites view error:", err);
    res.status(500).send("Failed to load favorites");
  }
});

/**
 * Add to favorites
 */

app.post("/favorites/add", requireLogin, async (req, res) => {
  const { recipeId, title, imageUrl, calories, protein } = req.body;
  const userId = req.session.userId;

  try {
    await upsertFoodRecipe(recipeId, title);

    const idNum = Number(recipeId) || 0;
    const cal = calories ? Number(calories) : 100 + (idNum % 400);
    const prot = protein ? Number(protein) : 5 + (idNum % 40);

    await pool.query(
      `INSERT INTO userFavorites 
       (userID, recipeID, title, imageUrl, calories, protein, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE
         title = VALUES(title),
         imageUrl = VALUES(imageUrl),
         calories = VALUES(calories),
         protein = VALUES(protein)`,
      [userId, Number(recipeId), title, imageUrl, cal, prot]
    );

    res.redirect(req.get("Referer") || "/recipes");
  } catch (err) {
    console.error("Favorites add error:", err);
    res.redirect(req.get("Referer") || "/recipes");
  }
});

/**
 * Remove favorite
 */
app.post("/favorites/remove", requireLogin, async (req, res) => {
  const { recipeId } = req.body;
  const userId = req.session.userId;

  try {
    await pool.query(
      "DELETE FROM userFavorites WHERE userID = ? AND recipeID = ?",
      [userId, recipeId]
    );
    res.redirect("/favorites");
  } catch (err) {
    console.error("Favorites remove error:", err);
    res.status(500).send("Failed to remove favorite");
  }
});

/* ============================================================
 *                        TRACKER ROUTES
 * ============================================================*/


app.get("/tracker", async (req, res) => {
  if (!req.session.isAuthenticated) {
    // guest → sample view (handled in EJS using totals=null, entries=null, editingEntry=null)
    return res.render("tracker.ejs", { totals: null, entries: null, editingEntry: null });
  }

  const userId = req.session.userId;
  const editId = req.query.editId ? Number(req.query.editId) : null;

  try {
    const [rows] = await pool.query(
      `SELECT id, recipeID, recipeTitle, calories, protein, carbs, fat, date_logged
         FROM tracker
        WHERE userID = ?
        ORDER BY date_logged DESC`,
      [userId]
    );

    const today = new Date().toISOString().slice(0, 10);

    const todayRows = rows.filter((r) => {
      const d =
        r.date_logged instanceof Date
          ? r.date_logged.toISOString().slice(0, 10)
          : String(r.date_logged).slice(0, 10);
      return d === today;
    });

    const totals = todayRows.reduce(
      (acc, r) => {
        acc.calories += r.calories || 0;
        acc.protein += Number(r.protein || 0);
        acc.carbs += Number(r.carbs || 0);
        acc.fat += Number(r.fat || 0);
        return acc;
      },
      { calories: 0, protein: 0, carbs: 0, fat: 0 }
    );

    const entries = todayRows.map((r) => ({
      id: r.id,
      recipeID: r.recipeID,
      recipeTitle: r.recipeTitle,
      calories: r.calories,
      protein: Number(r.protein || 0),
      carbs: Number(r.carbs || 0),
      fat: Number(r.fat || 0),
    }));

    const editingEntry = editId ? entries.find((e) => e.id === editId) || null : null;

    res.render("tracker.ejs", { totals, entries, editingEntry });
  } catch (err) {
    console.error("Tracker view error:", err);
    res.status(500).send("Failed to load tracker");
  }
});


app.post("/tracker/add-manual", requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const { meal, calories, protein, carbs, fat } = req.body;

  try {
    await pool.query(
      `INSERT INTO tracker 
         (userID, recipeID, recipeTitle, calories, protein, carbs, fat, date_logged)
       VALUES (?, NULL, ?, ?, ?, ?, ?, CURDATE())`,
      [
        userId,
        meal || "Meal",
        calories ? Number(calories) : 0,
        protein ? Number(protein) : 0,
        carbs ? Number(carbs) : 0,
        fat ? Number(fat) : 0,
      ]
    );

    res.redirect("/tracker");
  } catch (err) {
    console.error("Tracker manual add error:", err);
    res.status(500).send("Failed to add entry");
  }
});


app.post("/tracker/:id/edit", requireLogin, async (req, res) => {
  const { id } = req.params;
  const userId = req.session.userId;
  const { meal, calories, protein, carbs, fat } = req.body;

  try {
    await pool.query(
      `UPDATE tracker
          SET recipeTitle = ?,
              calories    = ?,
              protein     = ?,
              carbs       = ?,
              fat         = ?
        WHERE id = ? AND userID = ?`,
      [
        meal || "Meal",
        calories ? Number(calories) : 0,
        protein ? Number(protein) : 0,
        carbs ? Number(carbs) : 0,
        fat ? Number(fat) : 0,
        id,
        userId,
      ]
    );

    res.redirect("/tracker");
  } catch (err) {
    console.error("Tracker edit save error:", err);
    res.status(500).send("Failed to update entry");
  }
});


app.post("/tracker/:id/delete", requireLogin, async (req, res) => {
  const { id } = req.params;
  const userId = req.session.userId;

  try {
    await pool.query("DELETE FROM tracker WHERE id = ? AND userID = ?", [id, userId]);
    res.redirect("/tracker");
  } catch (err) {
    console.error("Tracker delete error:", err);
    res.status(500).send("Failed to delete entry");
  }
});


app.get("/tracker/portion/:recipeId", requireLogin, async (req, res) => {
  const { recipeId } = req.params;
  const recipeData = req.query.data;

  if (!recipeData) return res.redirect("/recipes");

  try {
    const recipe = JSON.parse(decodeURIComponent(recipeData));
    res.render("portionForm.ejs", { recipe, recipeId });
  } catch (err) {
    console.error("Portion form error:", err);
    res.redirect("/recipes");
  }
});

app.post("/tracker/:id/favorite", requireLogin, async (req, res) => {
  const { id } = req.params;
  const userId = req.session.userId;

  try {
    const [rows] = await pool.query(
      `SELECT id, recipeID, recipeTitle, calories, protein
         FROM tracker
        WHERE id = ? AND userID = ?`,
      [id, userId]
    );

    if (!rows.length) {
      // Entry not found or not owned by this user
      return res.redirect("/tracker");
    }

    const entry = rows[0];

    // If entry came from an API recipe, reuse that recipeID.
    // If it is a manual entry (recipeID is null), synthesize a unique ID
    // well outside typical API ranges to avoid collisions.
    let recipeId = entry.recipeID;
    const title =
      entry.recipeTitle ||
      (entry.recipeID ? `Recipe #${entry.recipeID}` : `Custom meal #${entry.id}`);

    if (!recipeId) {
      recipeId = 1000000 + entry.id; // quick & dirty synthetic ID
    }

    // Ensure the recipe exists in foodRecipes to satisfy FK
    await upsertFoodRecipe(recipeId, title);

    const cal = entry.calories != null ? Number(entry.calories) : null;
    const prot = entry.protein != null ? Number(entry.protein) : null;

    await pool.query(
      `INSERT INTO userFavorites 
         (userID, recipeID, title, imageUrl, calories, protein, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE
         title    = VALUES(title),
         imageUrl = VALUES(imageUrl),
         calories = VALUES(calories),
         protein  = VALUES(protein)`,
      [
        userId,
        Number(recipeId),
        title,
        null,     // no image for custom/manual meals 
        cal,
        prot,
      ]
    );

    res.redirect("/favorites");
  } catch (err) {
    console.error("Tracker favorite error:", err);
    res.status(500).send("Failed to favorite entry");
  }
});



app.post("/tracker/add", requireLogin, async (req, res) => {
  const { recipeId, recipeData, servings, recipeTitle } = req.body;
  const userId = req.session.userId;

  try {
    const parsed = JSON.parse(recipeData);
    const portionSize = Number(servings) || 1;

    const title =
      recipeTitle ||
      parsed.title ||
      parsed.name ||
      parsed.strMeal ||
      `Recipe #${recipeId}`;

    await upsertFoodRecipe(recipeId, title);

    const nutrition = await extractNutrition(parsed, portionSize);

    await pool.query(
      `INSERT INTO tracker 
       (userID, recipeID, recipeTitle, calories, protein, fat, carbs, date_logged)
       VALUES (?, ?, ?, ?, ?, ?, ?, CURDATE())`,
      [
        userId,
        Number(recipeId),
        title,
        nutrition.calories,
        nutrition.protein,
        nutrition.fat,
        nutrition.carbs,
      ]
    );

    res.redirect("/tracker");
  } catch (err) {
    console.error("Tracker add error:", err);
    res.status(500).send("Failed to add to tracker");
  }
});


app.get("/dbTest", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT CURDATE()");
    res.send(rows);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).send("Database error!");
  }
});


app.listen(3000, () => {
  console.log("Express server running");
});
