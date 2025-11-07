const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bearerToken = require('express-bearer-token');
require('dotenv').config();
const user = require('./user');

const PORT = process.env.PORT || 3000;

const app = express()
  .use(cors())
  .use(bodyParser.json())
  .use(bearerToken());

app.use('/', user)

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
