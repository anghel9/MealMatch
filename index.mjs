import "dotenv/config";
import { GoogleGenAI } from "@google/genai";
import express from "express";
import mysql from "mysql2/promise";
import session from "express-session";
import bcrypt from "bcrypt";

const apiKey = process.env.API_KEY;
const app = express();
const ai = new GoogleGenAI(process.env.GEMINI_API_KEY);

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

// middleware
function requireLogin(req, res, next) {
  if (req.session.isAuthenticated) return next();
  return res.redirect("/login");
}

// ----------------- BASIC ROUTES -----------------

app.get("/", async (req, res) => {
  res.render("home.ejs");
});

// ----------------- GEMINI / TRACKER -----------------

async function extractNutrition(recipeData) {
   const prompt = 
   `Analyze this recipe and return ONLY a JSON object with nutritional information per serving.
   Recipe: ${JSON.stringify(recipeData)}
   
   Return format (numbers only, no units):
   {
      "calories": number,
      "protein": number,
      "fat": number,
      "carbs": number
   }
   `;

   const model = ai.getGenerativeModel({ model: "gemini-2.0-flash-exp" });
   const result = await model.generateContent(prompt);
   const response = result.response;
   const text = response.text();

   // Parse the JSON response
   const jsonText = text.replace(/```json\n?|\n?```/g, '').trim();
   return JSON.parse(jsonText);
}

app.post("/tracker/add", requireLogin, async (req, res) => {
   const { recipeId, recipeData } = req.body;
   const userId = req.session.userId;

  try {
    const nutrition = await extractNutrition(JSON.parse(recipeData));

      // Insert into database
      await pool.query(
         `INSERT INTO tracker (userID, recipeID, calories, protein, fat, carbs, date_logged) 
          VALUES (?, ?, ?, ?, ?, ?, CURDATE())`,
         [
            userId,
            recipeId,
            nutrition.calories,
            nutrition.protein,
            nutrition.fat,
            nutrition.carbs
         ]
      );

    res.json({ success: true, nutrition });
  } catch (err) {
    console.error("Tracker error:", err);
    res.status(500).json({ error: "Failed to add to tracker" });
  }
});

app.get("/tracker/data", requireLogin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM tracker WHERE userID = ? ORDER BY date_logged DESC",
      [req.session.userId]
    );
    res.json(rows);
  } catch (err) {
    console.error("Tracker fetch error:", err);
    res.status(500).json({ error: "Failed to fetch tracker data" });
  }
});

// ----------------- ADMIN ROUTES -----------------

// Show admin login
app.get("/admin", (req, res) => {
  if (req.session.isAuthenticated && req.session.isAdmin) {
    return res.redirect("/admin/dashboard");
  }

  res.render("admin.ejs", { loginError: "" });
});




app.get("/admin/dashboard", requireAdmin, (req, res) => {
  res.render("adminDashboard.ejs");
});


function requireAdmin(req, res, next) {
  if (req.session.isAuthenticated && req.session.isAdmin) {
    return next();
  }
  return res.status(403).send("Access denied.");
}



// ----------------- RECIPES -----------------


app.get('/recipes/random', async (req, res) => {
   try {
      const url = `https://api.spoonacular.com/recipes/random?apiKey=${apiKey}`;
      let response = await fetch(url);
      let data = await response.json();
      console.log("Spoonacular response:", data);
      // Check if Spoonacular limit hit
      if (data.code === 402 || data.status === 'failure') {
         console.log("Spoonacular limit reached, using TheMealDB...");
         const fallbackUrl = `https://www.themealdb.com/api/json/v1/1/random.php`;
         response = await fetch(fallbackUrl);
         data = await response.json();
         const meals = data.meals || [];
         return res.render('recipesFallback.ejs', { meals });
      }

      const meals = data.recipes || [];
      
      res.render('recipes.ejs', { meals });
   } catch (err) {
      console.error("API error:", err);
      res.status(500).send("Error fetching recipes");
   }
});

app.get("/recipes", async (req, res) => {
  const keyword = req.query.keyword;

   try {
      const url = `https://api.spoonacular.com/recipes/findByIngredients?apiKey=${apiKey}&ingredients=${encodeURIComponent(keyword)}&number=9`;
      let response = await fetch(url);
      let data = await response.json();
      console.log("Spoonacular response:", data);
      //Check if Spoonacular limit hit
      if (data.code === 402 || data.status === 'failure') {
         console.log("Spoonacular limit reached, using TheMealDB...");
         const fallbackUrl = `https://www.themealdb.com/api/json/v1/1/search.php?s=${encodeURIComponent(keyword)}`;
         response = await fetch(fallbackUrl);
         data = await response.json();
         const meals = data.meals || [];
         return res.render('recipesFallback.ejs', { meals });
      }

      if (!Array.isArray(data)) {
         return res.render('recipes.ejs', { meals: [] });
      }

      const meals = await Promise.all(
         data.map(async (recipe) => {
         const detailUrl = `https://api.spoonacular.com/recipes/${recipe.id}/information?apiKey=${apiKey}`;
         const detailResponse = await fetch(detailUrl);
         return await detailResponse.json();
         })
      );
      
      res.render('recipes.ejs', { meals });
   } catch (err) {
      console.error("API error:", err);
      res.status(500).send("Error fetching recipes");
   }
});

// ----------------- USER AUTH (usersMM table, email login) -----------------

// show login page
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

// ----------------- REGISTRATION (usersMM) -----------------

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

// ----------------- FAVORITES / TRACKER PAGES (views) -----------------

app.get("/favorites", async (req, res) => {
  if (!req.session.isAuthenticated) {
    // Guest: let EJS show sample favorites
    return res.render("favorites.ejs", { favorites: null });
  }

  // Logged in: TODO load real favorites from DB.
  const favorites = [];
  res.render("favorites.ejs", { favorites });
});

app.get("/tracker", async (req, res) => {
  if (!req.session.isAuthenticated) {
    // Guest: let EJS show sample totals + sample entries
    return res.render("tracker.ejs", { totals: null, entries: null });
  }

  // Logged in: TODO load real tracker data from DB.
  const totals = null;
  const entries = [];
  res.render("tracker.ejs", { totals, entries });
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
});//dbTest

app.listen(3000, () => {
  console.log("Express server running");
});
