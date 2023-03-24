const express = require("express")
const app = express()
const jwt = require('jsonwebtoken')
require('dotenv').config()
const db = require('./database.js')
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');

app.set('view-engine', 'ejs')
app.use(express.urlencoded({extended: false}))
app.use(express.json())
app.use(cookieParser())

var currentKey =""

app.get('/', (req,res) => {
    res.redirect("/identify")
})

app.get('/identify', (req, res) => {
    res.render('identify.ejs')
})

app.post('/identify', async (req, res) => {
    try {
        if (!req.body.userId || !req.body.password) {
            throw new Error('Missing required fields: userId and password');
        }
        let dbUser = await db.getUser(req.body.userId);
        if (!dbUser) {
            throw new Error('User not found');
        }
        // Gets the encrypted password from the db
        var correctPassword = await db.getPasswordForUser(req.body.userId);
        // Compares the encrypted passwords
        var passwordMatches = await bcrypt.compare(req.body.password, correctPassword);
        if (!passwordMatches) {
            throw new Error('Invalid credentials');
        }
        let userObj = { username: req.body.userId, role: dbUser.role };
        const token = jwt.sign(userObj, process.env.ACCESS_TOKEN_SECRET);
        currentKey = token;
        res.cookie("jwt", token, { httpOnly: true }).status(200).redirect('/granted');
    } catch (error) {
        console.error(error);
        res.status(400).render('identify.ejs', { errorMessage: error.message });
    }
});

function authenticateToken(req, res, next) {
    if(currentKey == "") {
        res.redirect("/identify")
    } else if (jwt.verify(currentKey, process.env.ACCESS_TOKEN_SECRET)) {
        next()
    } else {
        res.redirect("/identify")
    }
}

app.get('/granted', authenticateToken, (req, res) => {
    res.render("start.ejs")
})

app.get('/admin',authenticateToken,authorizeRole(["ADMIN"]),async (req, res) => {
    users = await db.getAllUsers();
    res.render('admin.ejs', users)
})


async function Users(username, name, role, password) {
    let encryptedPassword = await bcrypt.hash(password, 10);
    await db.addUser(username, name, role, encryptedPassword);
}

function authorizeRole(requiredRoles) {
    return async (req, res, next) => {
      try {
        const user = await getUserFromToken(req);
  
        if (requiredRoles.includes(user.role)) {
          next();
        } else {
          res.sendStatus(401);
        }
      } catch (error) {
        console.log(error);
        res.sendStatus(401);
      }
    };
  }
  
  app.get('/student1', authenticateToken, authorizeRole(["STUDENT1","ADMIN","TEACHER"]), async (req, res) => {
    try {
        const user = await getUserFromToken(req);
        res.render('student1.ejs', { user: user })
    } catch (error) {
        console.error(error)
        res.status(500).render('fail.ejs', {error})
    }
})

app.get('/student2', authenticateToken, authorizeRole(["STUDENT2","ADMIN","TEACHER"]), async (req, res) => {
    try {
        const user = await getUserFromToken(req);
        res.render('student2.ejs', { user: user })
    } catch (error) {
        console.error(error)
        res.status(500).render('fail.ejs', {error})
    }
})

app.get('/teacher', authenticateToken, authorizeRole(["TEACHER","ADMIN"]), async (req, res) => {
    try {
        const user = await getUserFromToken(req);
        res.render('teacher.ejs')
    } catch (error) {
        console.error(error)
        res.status(500).render('fail.ejs', {error})
    }
})

async function getUserFromToken(req) {
    const token = req.cookies.jwt;
    const decryptedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await db.getUser(decryptedToken.username);
    return user;
}


Users('id1','user1', 'STUDENT1', 'password');
Users('id2','user2', 'STUDENT2', 'password2');
Users('id3', 'user3', 'TEACHER', 'password3');
Users('admin', 'admin', 'ADMIN', 'admin');

app.listen(8000, () => {
console.log("Server is up on port 8000")
})