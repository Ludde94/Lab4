const express = require("express")
const app = express()
const jwt = require('jsonwebtoken')
require('dotenv').config()
const db = require('./database.js')
const bcrypt = require('bcrypt');

app.set('view-engine', 'ejs')
app.use(express.urlencoded({extended: false}))
app.use(express.json())

var currentKey =""
var currentPassword =""

app.get('/', (req,res) => {
    res.redirect("/identify")
})

app.get('/identify', (req, res) => {
    res.render('identify.ejs')
})

app.post('/identify', async (req, res) => {
    if (req.body.userId && req.body.password) {
        // Gets the encrypted password from the db
        var correctPassword = await db.getPasswordForUser(req.body.userId)
        // Compares the encrypted passwords
        var passwordMatches = await bcrypt.compare(req.body.password, correctPassword)
        if (passwordMatches) {
            const username = req.body.password
            const token = jwt.sign(username, process.env.ACCESS_TOKEN_SECRET)
            currentKey = token
            currentPassword = username
            res.redirect("/granted")
        }
    }
})

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

app.get('/admin',async (req, res) => {
    users = await db.getAllUsers();
    res.render('admin.ejs', users)
  })

async function Users(username, name, role, password) {
    let encryptedPassword = await bcrypt.hash(password, 10);
    await db.addUser(username, name, role, encryptedPassword);
}

Users('id1','user1', 'STUDENT1', 'password');
Users('id2','user2', 'STUDENT2', 'password2');
Users('id3', 'user3', 'TEACHER', 'password3');
Users('admin', 'admin', 'ADMIN', 'admin');

app.listen(8000, () => {
console.log("Server is up on port 8000")
})