const express = require('express');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database(':memory:');

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

module.exports = router;
