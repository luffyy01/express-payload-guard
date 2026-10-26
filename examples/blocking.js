const express = require('express');
const payloadGuard = require('../index');

const app = express();
app.use(express.json());

// Strict mode: Rejects requests containing malicious keys with 400 Bad Request
app.post('/api/login', payloadGuard({ block: true, xss: true }), (req, res) => {
  res.json({
    message: 'Login credentials accepted for validation',
    user: req.body.username
  });
});

if (require.main === module) {
  app.listen(3000, () => {
    console.log('Strict guard server running on http://localhost:3000');
  });
}

module.exports = app;
