const nJwt = require('njwt');
const JWT_SECRET = process.env.JWT_SECRET || 'auth-secret-key';

function jwtAuth(req, res, next) {
  if (!req.token) {
    return res.status(403).send({ auth: false, message: 'No token provided' });
  }

  nJwt.verify(req.token, JWT_SECRET, function(err, decoded) {
    if (err) {
      return res.status(500).send({ auth: false, message: 'Could not authenticate token' });
    }
    req.userId = decoded.body.id;
    next();
  });
}

module.exports = jwtAuth;
