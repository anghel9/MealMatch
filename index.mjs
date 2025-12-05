import 'dotenv/config';
import express from "express";
import mysql from "mysql2/promise";
import session from "express-session";
import bcrypt from "bcrypt";

const apiKey= process.env.API_KEY;
const app = express();

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
   res.render('home.ejs')
});

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


//ADDING IN THE ADMIN PAGE
app.get("/admin", async (req, res) => {
   if (req.session.isAuthenticated) {
      return res.redirect("/adminDashboard.ejs");
   }
   res.render("admin.ejs", { title: "Admin Login", loginError: "" });
});

app.post('/adminProcess', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Query the database for this username
    const sql = `
      SELECT userId, username, password AS hashedPassword, firstName, lastName
      FROM users
      WHERE username = ?
      LIMIT 1;
    `;
    const [rows] = await pool.query(sql, [username]);

    // If no user found
    if (rows.length === 0) {
      return res.render('admin.ejs', {
        loginError: "Invalid username or password"
      });
    }

    const user = rows[0];

    // Compare password using bcrypt
    const isMatch = await bcrypt.compare(password, user.hashedPassword);

    if (!isMatch) {
      return res.render('admin.ejs', {
        loginError: "Invalid username or password"
      });
    }

    // Successful login → store session info
    req.session.isUserAuthenticated = true;
    req.session.userId = user.userId;
    req.session.username = user.username;
    req.session.fullName = `${user.firstName} ${user.lastName}`;

    

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("Server error during login.");
  }
});


// show login page
app.get("/login", async (req, res) => {
   if (req.session.isAuthenticated) {
      return res.redirect("/");
   }
   res.render("login.ejs", { title: "Login", loginError: "" });
});
app.post('/loginProcess', async (req, res) => {
    let username = req.body.username;
    let password = req.body.password;

    let hashedPassword = "";
    let sql = `SELECT *
               FROM users
              WHERE username = ?`;
    const [rows] = await pool.query(sql, [username]); 

    if (rows.length > 0) { //username exists in the table
      hashedPassword = rows[0].password;
    }

    const match = await bcrypt.compare(password, hashedPassword);

    if (match) {
        req.session.isUserAuthenticated = true;
        req.session.fullName = rows[0].firstName + " " + rows[0].lastName;
        res.render('home.ejs')
    } else {
        res.render('login.ejs', {"loginError": "Wrong Credentials" })
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

   if (!username || !email || !password || password !== confirm){
      return res.render("create.ejs", {
         title: "Create Account",
         registerError: "Please fill all fields and make sure passwords match.",   
      });
   }

   try{
      const [existing] = await pool.query(
         "SELECT * FROM usersMM WHERE email = ? OR username = ?",
         [email, username]
      );

      if (existing.length){
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
   } catch (err){
      console.error("Registration error:", err);
      res.status(500).send("Server error during registration.");
   }
});

// this is viewbable by everyone for now, but we will restrict it later
app.get("/favorites", async (req, res) => {
   res.render("favorites.ejs");
});

app.get("/tracker", async (req, res) => {
   res.render("tracker.ejs");
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



function isUserAuthenticated(req, res, next){
 if (req.session.isUserAuthenticated) {
    next();
   } else {
    res.redirect("/");
   }
}


app.listen(3000, () => {
   console.log("Express server running")
});
