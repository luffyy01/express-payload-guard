# express-payload-guard

Lightweight, zero-dependency Express middleware and standalone utility to sanitize incoming request payloads against NoSQL injection, prototype pollution, XSS tags, and oversized nested objects.

[![npm version](https://img.shields.io/npm/v/express-payload-guard.svg)](https://www.npmjs.com/package/express-payload-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Why?

When building Node.js/Express APIs, unvalidated client inputs can expose applications to several common vulnerabilities:
- **NoSQL Injection:** Attackers pass MongoDB query operators (`{ "$gt": "" }`, `$where`) in JSON bodies or query strings to bypass authentication or leak records.
- **Prototype Pollution:** Payloads with keys like `__proto__`, `constructor`, or `prototype` can mutate object prototypes across the Node process.
- **Unsanitized HTML/Scripts:** User inputs with embedded `<script>` or HTML tags can persist to storage and trigger XSS vulnerabilities.
- **DoS via Deep Nesting:** Circular or deeply nested JSON payloads can trigger maximum call stack errors or block the event loop.

`express-payload-guard` gives you a fast, zero-dependency middleware that strips or blocks these patterns automatically.

## Installation

```bash
npm install express-payload-guard
```

## Quick Start

### As Express Middleware (Default: Silent Sanitize)

By default, the middleware recursively inspects `req.body`, `req.query`, and `req.params`, removes malicious keys in-place, trims strings, and forwards the cleaned request to your route handler:

```javascript
const express = require('express');
const payloadGuard = require('express-payload-guard');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Apply globally to all incoming requests
app.use(payloadGuard());

app.post('/api/users', (req, res) => {
  // Any $ operators or __proto__ keys are already stripped
  // Strings have leading/trailing whitespace removed
  res.json({ data: req.body });
});

app.listen(3000);
```

### Strict Mode (Block & Reject with 400)

If you prefer to reject suspicious requests rather than sanitizing them silently, set `block: true`:

```javascript
app.post('/api/login', payloadGuard({ block: true }), (req, res) => {
  // If req.body contains $gt, $ne, or __proto__, request is halted with 400 Bad Request
  res.json({ status: 'ok' });
});
```

Example 400 error response:
```json
{
  "status": 400,
  "error": "Bad Request",
  "message": "Potentially malicious input detected.",
  "violations": [
    "NoSQL operator key '$gt' removed"
  ]
}
```

### Standalone Utility (Outside Express)

You can also use the sanitizer directly anywhere in your Node.js application (e.g. background jobs, WebSockets, serverless handlers):

```javascript
const { sanitize } = require('express-payload-guard');

const rawInput = {
  name: '  John Doe  ',
  filter: { $where: 'evil()' },
  content: '<script>alert(1)</script>Hello'
};

const result = sanitize(rawInput, { xss: true });

console.log(result.isValid); // false
console.log(result.data); 
// { name: 'John Doe', filter: {}, content: 'alert(1)Hello' }
console.log(result.violations);
// [ { type: 'NOSQL_INJECTION', key: '$where', message: "..." }, ... ]
```

## Configuration Options

Pass an options object when initializing `payloadGuard(options)` or calling `sanitize(input, options)`:

| Option | Type | Default | Description |
|---|---|---|---|
| `body` | `boolean` | `true` | Sanitize `req.body` |
| `query` | `boolean` | `true` | Sanitize `req.query` |
| `params` | `boolean` | `true` | Sanitize `req.params` |
| `noSql` | `boolean` | `true` | Strip keys starting with `$` or containing `.` |
| `protoPollution` | `boolean` | `true` | Strip `__proto__`, `constructor`, `prototype` |
| `trim` | `boolean` | `true` | Automatically trim whitespace on all string values |
| `xss` | `boolean` | `false` | Strip HTML/script tags from strings |
| `maxDepth` | `number` | `10` | Maximum allowed object nesting depth before dropping nodes |
| `block` | `boolean` | `false` | Reject request with 400 instead of silently cleaning |
| `whitelist` | `string[]` | `[]` | Array of keys permitted even if they match NoSQL pattern |
| `onViolation` | `function` | `null` | Custom callback `(req, res, next, violations) => void` |

### Custom Violation Handler

If you want to log violations to your application logger (e.g. Pino, Winston) or emit security alerts:

```javascript
app.use(payloadGuard({
  onViolation: (req, res, next, violations) => {
    console.warn(`[SECURITY ALERT] Path: ${req.path}`, violations);
    res.status(400).json({ error: 'Invalid input format' });
  }
}));
```

## Running Tests

The test suite uses Node's native test runner (`node:test`) and requires no external testing frameworks:

```bash
npm test
```

## Limitations

- `express-payload-guard` strips common injection patterns from request bodies and query parameters. For complete defense-in-depth, always combine input sanitization with database-level validation (e.g. Mongoose schemas, Zod/Joi schema validation, parameterized SQL queries).
- When `xss: true` is enabled, basic HTML tags are stripped using regex. For rich HTML text inputs (e.g. blog editors), use a dedicated HTML parser like DOMPurify or sanitize-html with custom tag rules.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Write tests for your changes in `test/`
4. Run tests with `npm test`
5. Commit your changes (`git commit -m 'feat: add my feature'`)
6. Push to the branch (`git push origin feature/my-feature`)
7. Open a Pull Request

## License

MIT © [luffyy01](https://github.com/luffyy01)
