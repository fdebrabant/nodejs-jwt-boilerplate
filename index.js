const express = require('express');
const cors = require('cors');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const connection = require('./database');


const { SERVER_PORT, CLIENT_URL, JWT_SECRET } = process.env;

const app = express();

app.use(
  cors({
    origin: CLIENT_URL,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Your code here!

// authentification avec middleware

// Token middleware
const authenticateWithJsonWebToken = (req, res, next) => {
  if (req.headers.authorization !== undefined) {
    const token = req.headers.authorization.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err) => {
      if (err) {
        res
          .status(401)
          .json({ errorMessage: "you're not allowed to access these data" });
      } else {
        next();
      }
    });
  } else {
    res
      .status(401)
      .json({ errorMessage: "you're not allowed to access these data" });
  }
};

// Authenticated route
app.get('/users', authenticateWithJsonWebToken, (req, res) => {
  connection.query(`SELECT * FROM user`, (error, result) => {
    if (error) {
      res.status(500).json({ errorMessage: error.message });
    } else {
      res.status(200).json(
        result.map((user) => {
          return { ...user, password: 'hidden' };
        })
      );
    }
  });
});

// post an user with a crypted password

app.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res
      .status(400)
      .json({ errorMessage: 'Please specify both email and password' });
  } else {
    const hash = bcrypt.hashSync(password, 10);
    connection.query(
      `INSERT INTO user(email, password) VALUES (?, ?)`,
      [email, hash],
      (error, result) => {
        if (error) {
          res.status(500).json({ errorMessage: error.message });
        } else {
          res.status(201).json({
            id: result.insertId,
            email,
            password: 'hidden',
          });
        }
      }
    );
  }
});

// conexion d'un compte utilisateur

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password){
    res
    .status(400)
    .json({ errorMessage: 'Please specify both email and password' });
  } else {
    connection.query(
      `SELECT * FROM user WHERE email=?`,
      [email],
      (error, result)=> {
        if (error){
          res
          .status(500)
          .json({errorMessage: error.message});
        } else if (result.length===0){
          res.send(403).json({errorMessage: 'Invalid email'})
        } else if (bcrypt.compareSync(password, result[0].password)){
          // password check
          const user = {
            id: result[0].id,
            email,
            password:"hidden"
          };
          // generate token
          const token = jwt.sign({ id: user.id }, JWT_SECRET, {
            expiresIn: '1h',
          });
          res.status(200).json({user, token});
        } else {
          res.status(403).json({ errorMessage: 'Invalid password' });
        }
      }
    )
  }
});


// Don't write anything below this line!
app.listen(SERVER_PORT, () => {
  console.log(`Server is running on port ${SERVER_PORT}.`);
});
