import 'dotenv/config';
import { GoogleGenAI } from "@google/genai";
import express from "express";
import mysql from "mysql2/promise";
import session from "express-session";
import bcrypt from "bcrypt";

const apiKey = process.env.API_KEY;
const app = express();
const ai = new GoogleGenAI({});

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

//setting up database connection pool
const pool = mysql.createPool({
  host: process.env.HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DATABASE,
  connectionLimit: 10,
  waitForConnections: true
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
  next();
});

// middleware
function requireLogin(req, res, next) {
  if (req.session.isAuthenticated) return next();
  return res.redirect("/login");
}

//routes
app.get('/', async (req, res) => {
   console.log(response.text);
   res.render('home.ejs')

});

async function extractNutrition(recipeData) {
   const prompt = 
   `Analyze this recipe and return ONLY a JSON object with nutritional information per serving.
   Recipe: ${JSON.stringify(recipeData)}
   
   Return format (numbers only, no units):
   {
      "calories": number,
      "protein": number,
      "fat": number,
      "carbs": number,
      "fiber": number,
      "sugar": number,
      "sodium": number
   }
   `;

   const response = await ai.models.generateContent({
      model: "gemini-2.0-flash-exp",
      contents: prompt,
   });

   // Parse the JSON response
   const jsonText = response.text.replace(/```json\n?|\n?```/g, '').trim();
   return JSON.parse(jsonText);
}

app.get('/recipes/random', async (req, res) => {
  try {
    const url = `https://api.spoonacular.com/recipes/random?apiKey=${apiKey}`;
    let response = await fetch(url);
    let data = await response.json();

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

app.get('/recipes', async (req, res) => {
  let keyword = req.query.keyword;

  try {
    const url = `https://api.spoonacular.com/recipes/findByIngredients?apiKey=${apiKey}&ingredients=${encodeURIComponent(keyword)}&number=9`;
    let response = await fetch(url);
    let data = await response.json();

    // Check if Spoonacular limit hit
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
    // make sure that it is usersMM not users (since that is from lab7)
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

// this is viewbable by everyone for now, but we will restrict it later
app.get("/favorites", async (req, res) => {
  if (!req.session.isAuthenticated) {
    // Guest: let EJS show sample favorites
    return res.render("favorites.ejs", { favorites: null });
  }

  // Logged in: TODO load real favorites from DB.
  // For now pass an empty array so the template can say "no favorites yet".
  const favorites = [];
  res.render("favorites.ejs", { favorites });
});

app.get("/tracker", async (req, res) => {
  if (!req.session.isAuthenticated) {
    // Guest: let EJS show sample totals + sample entries
    return res.render("tracker.ejs", { totals: null, entries: null });
  }

  // Logged in: TODO load real tracker data from DB.
  // For now, totals=null (so EJS can default to zeros) and no entries.
  const totals = null;
  const entries = [];
  res.render("tracker.ejs", { totals, entries });
});

// fix this later, we will need the users table in the database to fully
// implement user creation and authentication. 

// Handle the POST from create.ejs (placeholder logic for now)
// (NOTE: this block is now obsolete; keeping the comment, but route removed)

//   // minimal guard; you’ll replace with real validation & DB insert
//   if (!email || !password || password !== confirm) {
//      return res.status(400).send("Invalid form submission.");
//   }

//   // TODO: insert into DB (users table) with hashed password
//   // Example (only if you already have a users table):
//   // await pool.execute(
//   //   "INSERT INTO users (email, password_hash) VALUES (?, ?)",
//   //   [email, someHashedPassword]
//   // );

//   // for now, just redirect to login and fix later
//   res.redirect("/login");
// });

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
