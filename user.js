const express = require('express');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database(':memory:');

const JWT_SECRET = process.env.JWT_SECRET || 'auth-secret-key';
const nJwt = require('njwt');
const jwtAuth = require('./auth');

db.serialize(() => {
  db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, fullName TEXT, email TEXT, password TEXT)', (err) => {
        if (err) {
            console.error(err.message);
        } else {
            console.log('Table created or already exists.');
        }
    });
});

const router = express.Router();

router.post('/register', function(req, res) {
  var hashedPassword = bcrypt.hashSync(req.body.password, 8);
  const fullName = req.body.fullName;
  const email = req.body.email;

    db.run('INSERT INTO users (fullName, email, password) VALUES (?, ?, ?)',
    [fullName, email, hashedPassword], 
    function(err) {
        if (err) return res.status(500).send("An error occurred during registration");

        res.status(201).send({ 
            status: 'ok', 
            message: 'Registered successfully', 
            success: true 
        });
    });
});

router.post('/login', function(req, res) {
    const email = req.body.email;
    const password = req.body.password;

    db.get('SELECT id, fullName, email, password FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).send({status: 'Server error', err:err});
        if (!user) return res.status(404).send('User not found');

        if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).send({ auth: false, token: null });
        }

        var jwt = nJwt.create({ 
            id: user.id, 
            email: user.email, 
            fullName: user.fullName }, JWT_SECRET);
        jwt.setExpiration(new Date().getTime() + (24*60*60*1000));

        res.status(200).send({ 
            auth: true, 
            token: jwt.compact(), 
            success: true, 
            message: 'Login successful' 
        });
    });
});

router.get('/user', jwtAuth, function(req, res, next) {
    const userId = req.userId;

    db.get('SELECT id, fullName, email FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            return res.status(500).send("There was a problem finding the user.");
        }
        if (!user) {
            return res.status(404).send("No user found.");
        }
        res.status(200).send({user: user, success: true});
    });
});

module.exports = router;
