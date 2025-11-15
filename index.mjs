import express from "express";
import mysql from 'mysql2/promise';
const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));

//setting up database connection pool
const pool = mysql.createPool({
    host: "sh4ob67ph9l80v61.cbetxkdyhwsb.us-east-1.rds.amazonaws.com",
    user: "w9c7lwn8um1o99yj",
    password: "u3rw8lbcasz2h307",
    database: "pyn5h5u7iu857dd2",
    connectionLimit: 10,
    waitForConnections: true
});

//routes
app.get('/', async(req, res) => {
   res.render('home.ejs')
});

app.get('/recipes/random', async(req, res) => {
   const url = `https://www.themealdb.com/api/json/v1/1/random.php`;
   let response = await fetch(url);
   let data = await response.json();
   const meals = data.meals || [];
   res.render('recipes.ejs', { meals })
});

app.get('/searchByLetter', async(req, res) => {
   let letter = req.query.letter;
   const url = `https://www.themealdb.com/api/json/v1/1/search.php?f=${encodeURIComponent(letter)}`;
   let response = await fetch(url);
   let data = await response.json();
   const meals = data.meals || [];
   res.render('recipess.ejs', { meals})
});

app.get('/recipes', async(req, res) => {
 
   let keyword = req.query.keyword;
   const url = `https://www.themealdb.com/api/json/v1/1/search.php?s=${encodeURIComponent(keyword)}`;
   let response = await fetch(url);
   let data = await response.json();
   const meals = data.meals || [];
   res.render('recipes.ejs', { meals })
});




app.get("/dbTest", async(req, res) => {
   try {
        const [rows] = await pool.query("SELECT CURDATE()");
        res.send(rows);
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).send("Database error!");
    }
});//dbTest

app.listen(3000, ()=>{
    console.log("Express server running")
})