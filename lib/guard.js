const { cleanValue } = require('./sanitize');

function payloadGuard(options = {}) {
  const opts = {
    body: true,
    query: true,
    params: true,
    noSql: true,
    protoPollution: true,
    trim: true,
    xss: false,
    maxDepth: 10,
    block: false,
    whitelist: [],
    onViolation: null,
    ...options
  };

  return function (req, res, next) {
    const targets = [];
    if (opts.body && req.body) targets.push('body');
    if (opts.query && req.query) targets.push('query');
    if (opts.params && req.params) targets.push('params');

    const violations = [];

    for (const target of targets) {
      const targetViolations = [];
      req[target] = cleanValue(req[target], opts, targetViolations, 0);

      if (targetViolations.length > 0) {
        for (const v of targetViolations) {
          violations.push({ target, ...v });
        }
      }
    }

    if (violations.length > 0) {
      if (typeof opts.onViolation === 'function') {
        return opts.onViolation(req, res, next, violations);
      }

      if (opts.block) {
        return res.status(400).json({
          status: 400,
          error: 'Bad Request',
          message: 'Potentially malicious input detected.',
          violations: violations.map(v => v.message)
        });
      }
    }

    next();
  };
}

module.exports = payloadGuard;
