const express = require('express');
const payloadGuard = require('../index');

const app = express();
app.use(express.json());

// Global guard: sanitizes body, query, and params in place
app.use(payloadGuard());

app.post('/api/users', (req, res) => {
  // Any $ operators or prototype keys are automatically stripped
  // Strings have extra whitespace trimmed
  res.json({
    success: true,
    data: req.body
  });
});

if (require.main === module) {
  app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
  });
}

module.exports = app;
