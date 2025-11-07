const express = require('express');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database(':memory:');

const JWT_SECRET = process.env.JWT_SECRET || 'auth-secret-key';
const nJwt = require('njwt');

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

        res.status(200).send({ status: 'ok' });
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

        var jwt = nJwt.create({ id: user.id }, JWT_SECRET);
        jwt.setExpiration(new Date().getTime() + (24*60*60*1000));

        res.status(200).send({ auth: true, token: jwt.compact() });
    });
});

module.exports = router;
