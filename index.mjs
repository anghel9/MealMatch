import "dotenv/config";
import express from "express";
import mysql from "mysql2/promise";
import session from "express-session";
import bcrypt from "bcrypt";
// Gemini import left out for now since tracker teammate can add it later
// import { GoogleGenAI } from "@google/genai";

const apiKey = process.env.API_KEY;
const app = express();

// const ai = new GoogleGenAI(process.env.GEMINI_API_KEY); // unused for now

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

// setting up database connection pool
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

function requireLogin(req, res, next) {
  if (req.session.isAuthenticated) return next();
  return res.redirect("/login");
}

function requireAdmin(req, res, next) {
  if (req.session.isAuthenticated && req.session.isAdmin) {
    return next();
  }
  return res.status(403).send("Access denied.");
}

async function upsertFoodRecipe(recipeId, title) {
  const id = Number(recipeId);

  
  const ingredients  = "Imported from API";
  const instructions = "See external recipe link for details.";
  const isFavorite   = 1; // mark as favorite in the db

  await pool.query(
    `INSERT INTO foodRecipes (recipeID, title, ingredients, instructions, isFavorite)
     VALUES (?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       title        = VALUES(title),
       ingredients  = VALUES(ingredients),
       instructions = VALUES(instructions),
       isFavorite   = VALUES(isFavorite)`,
    [id, title, ingredients, instructions, isFavorite]
  );
}


// ----------------- BASIC ROUTES -----------------

app.get("/", async (req, res) => {
  res.render("home.ejs");
});

// ----------------- ADMIN ROUTES -----------------

app.get("/admin", (req, res) => {
  if (req.session.isAuthenticated && req.session.isAdmin) {
    return res.redirect("/admin/dashboard");
  }

  res.render("admin.ejs", { loginError: "" });
});

app.get("/admin/dashboard", requireAdmin, (req, res) => {
  res.render("adminDashboard.ejs");
});

// ----------------- RECIPES -----------------

app.get("/recipes/random", async (req, res) => {
  try {
    const url = `https://api.spoonacular.com/recipes/random?apiKey=${apiKey}`;
    let response = await fetch(url);
    let data = await response.json();
    console.log("Spoonacular response:", data);

    if (data.code === 402 || data.status === "failure") {
      console.log("Spoonacular limit reached, using TheMealDB...");
      const fallbackUrl = `https://www.themealdb.com/api/json/v1/1/random.php`;
      response = await fetch(fallbackUrl);
      data = await response.json();
      const meals = data.meals || [];
      return res.render("recipesFallback.ejs", { meals, keyword: "" });
    }

    const meals = data.recipes || [];
    res.render("recipes.ejs", { meals, keyword: "" });
  } catch (err) {
    console.error("API error:", err);
    res.status(500).send("Error fetching recipes");
  }
});

app.get("/recipes", async (req, res) => {
  const keyword = (req.query.keyword || "").trim();

  if (!keyword) {
    return res.render("recipes.ejs", { meals: [], keyword: "" });
  }

  try {
    const url = `https://api.spoonacular.com/recipes/findByIngredients?apiKey=${apiKey}&ingredients=${encodeURIComponent(
      keyword
    )}&number=9`;
    let response = await fetch(url);
    let data = await response.json();
    console.log("Spoonacular response:", data);

    if (data.code === 402 || data.status === "failure") {
      console.log("Spoonacular limit reached, using TheMealDB...");
      const fallbackUrl = `https://www.themealdb.com/api/json/v1/1/search.php?s=${encodeURIComponent(
        keyword
      )}`;
      response = await fetch(fallbackUrl);
      data = await response.json();
      const meals = data.meals || [];
      return res.render("recipesFallback.ejs", { meals, keyword });
    }

    if (!Array.isArray(data)) {
      return res.render("recipes.ejs", { meals: [], keyword });
    }

    const meals = await Promise.all(
      data.map(async (recipe) => {
        const detailUrl = `https://api.spoonacular.com/recipes/${recipe.id}/information?apiKey=${apiKey}`;
        const detailResponse = await fetch(detailUrl);
        return await detailResponse.json();
      })
    );

    res.render("recipes.ejs", { meals, keyword });
  } catch (err) {
    console.error("API error:", err);
    res.status(500).send("Error fetching recipes");
  }
});

// ----------------- USER AUTH -----------------

app.get("/login", async (req, res) => {
  if (req.session.isAuthenticated) {
    return res.redirect("/");
  }
  res.render("login.ejs", { title: "Login", loginError: "" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query(
      "SELECT * FROM usersMM WHERE email = ?",
      [email]
    );

    if (!rows.length) {
      return res.render("login.ejs", {
        title: "Login",
        loginError: "Invalid email or password.",
      });
    }

    const user = rows[0];

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render("login.ejs", {
        title: "Login",
        loginError: "Invalid email or password.",
      });
    }

    req.session.isAuthenticated = true;
    req.session.userId = user.userID;
    req.session.userName = user.username;
    req.session.isAdmin = user.isAdmin === 1 || user.isAdmin === "1";

    res.redirect("/");
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("Server error during login.");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/create", async (req, res) => {
  if (req.session.isAuthenticated) {
    return res.redirect("/");
  }
  res.render("create.ejs", { title: "Create Account", registerError: "" });
});

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

// ----------------- FAVORITES -----------------

app.get("/favorites", async (req, res) => {
  const sort = req.query.sort || "name";

  if (!req.session.isAuthenticated) {
    return res.render("favorites.ejs", { favorites: null, sort });
  }

  try {
    const userId = req.session.userId;

    let orderBy = "title";
    if (sort === "calories") orderBy = "calories";
    else if (sort === "protein") orderBy = "protein";

    const [rows] = await pool.query(
      `SELECT recipeID, title, imageUrl, calories, protein
         FROM userFavorites
        WHERE userID = ?
        ORDER BY ${orderBy} ASC, title ASC`,
      [userId]
    );

    res.render("favorites.ejs", { favorites: rows, sort });
  } catch (err) {
    console.error("Favorites view error:", err);
    res.status(500).send("Failed to load favorites");
  }
});

app.post("/favorites/add", requireLogin, async (req, res) => {
  const { recipeId, title, imageUrl, calories, protein } = req.body;
  const userId = req.session.userId;

  try {
    const cal  = calories ? Number(calories) : null;
    const prot = protein  ? Number(protein)  : null;

    // insert an ignore since we do not want users to add dupe favorites
    await pool.query(
      `INSERT IGNORE INTO foodRecipes
         (recipeID, title, ingredients, instructions, isFavorite)
       VALUES (?, ?, ?, ?, 1)`,
      [
        recipeId,
        title,
        "Imported from external API",   // placeholder ingredients
        "See original recipe source.",  // placeholder instructions
      ]
    );

    
    await pool.query(
      `INSERT INTO userFavorites 
         (userID, recipeID, title, imageUrl, calories, protein, createdAt)
       VALUES (?, ?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE
         title    = VALUES(title),
         imageUrl = VALUES(imageUrl),
         calories = VALUES(calories),
         protein  = VALUES(protein)`,
      [userId, recipeId, title, imageUrl, cal, prot]
    );

    // Go back to the page the user was on (so they can keep browsing).
    const referer = req.get("Referer") || "/recipes";
    res.redirect(referer);
  } catch (err) {
    console.error("Favorites add error:", err);
    res.status(500).send("Failed to add favorite");
  }
});

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

// ----------------- TRACKER (simple placeholder) -----------------

app.get("/tracker", async (req, res) => {
  if (!req.session.isAuthenticated) {
    // guest → sample view (handled in EJS using totals=null, entries=null)
    return res.render("tracker.ejs", { totals: null, entries: null });
  }

  const userId = req.session.userId;

  try {
    const [rows] = await pool.query(
      `SELECT recipeID, calories, protein, carbs, fat, date_logged
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
      meal: `Recipe #${r.recipeID}`,
      calories: r.calories,
      protein: Number(r.protein || 0),
      carbs: Number(r.carbs || 0),
      fat: Number(r.fat || 0),
    }));

    res.render("tracker.ejs", { totals, entries });
  } catch (err) {
    console.error("Tracker view error:", err);
    res.status(500).send("Failed to load tracker");
  }
});

// basic add since anghel will take a look at this
app.post("/tracker/add", requireLogin, async (req, res) => {
  const { recipeId, recipeData } = req.body;
  const userId = req.session.userId;

  try {
    const parsed = JSON.parse(recipeData);

    const title =
      parsed.title ||
      parsed.name ||
      parsed.strMeal ||
      `Recipe #${recipeId}`;

    // Ensure base recipe exists for FK
    await upsertFoodRecipe(recipeId, title);

    // Use Gemini to get nutrition (your teammate can refine this)
    const nutrition = await extractNutrition(parsed);

    await pool.query(
      `INSERT INTO tracker (userID, recipeID, calories, protein, fat, carbs, date_logged) 
       VALUES (?, ?, ?, ?, ?, ?, CURDATE())`,
      [
        userId,
        Number(recipeId),
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


// ----------------- DB TEST -----------------

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
