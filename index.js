const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cors = require('cors')
const jwt = require('jsonwebtoken');
require('dotenv').config()

app.use(bodyParser.json())
app.use(cors({
    credentials: true,
    origin: 'http://localhost:3000',
}))

const port = 8000;

let conn = null
const connectMysql = async () => {
     conn = await mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: process.env.DB_ROOT_PASSWORD,
        database: 'tutorialauthen',
     })
}
app.get('/users', async (req,res) => {
    const result = await conn.query("SELECT * FROM users")
    res.json({
        result: result[0]
    })
})

app.post('/api/register', async (req,res) => {
    try {
        const {email,password} = req.body;
    
        const [Checkuser] = await conn.query("SELECT * FROM users WHERE email = ?", email)
        if(Checkuser.length > 0){
            return res.json({message: "Email already Registerd"})
        }
        if(password.length < 8){
            return res.json({message: "password must have at least 8 characters"})
        }
        const passwordHash =  await bcrypt.hash(password, 10)
        const userData = {
            email,
            password: passwordHash
        }
        const [result] = await conn.query("INSERT INTO users SET ?", userData)
        if(!result){
            throw Error
        }
        res.json({
            message: "register success",
            user: userData
        })
    } catch (error) {
        console.log("error", error)
    }


})

app.post('/api/login', async (req,res) => {
    try {
        const {email,password} = req.body
        const [result] = await conn.query("SELECT * FROM users WHERE email = ?", email)
        if(result.length === 0){
            return res.json({message: "User not found"})
        }
        const Checkhash = await bcrypt.compare(password, result[0].password)
        if(!Checkhash){
            return res.json({message: "Password Invalid"})
        }
        const token = jwt.sign({email}, process.env.My_secret, {expiresIn: '1h'})
        res.json({
            message: "ok",
            token
        })

    } catch (error) {
        console.log({"error": error})
    }

})


app.post("/api/authen", async (req,res)=> {
    try {
        const authheaders = req.headers['authorization'];
        const authToken = authheaders && authheaders.split(" ")[1];
        if(!authheaders){
            return res.status(401).json({message: "Required Token"})
        }

        const user =  jwt.verify(authToken, process.env.My_secret)

        if(!user){
            console.log("Invalid Token")
            return res.status(401).json({message: "Invalid Token"})
        }
        res.json({
            message: "ok",
            user
        })

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
    })


app.listen(port, async (req,res) => {
    connectMysql()
})

















