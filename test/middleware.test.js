const test = require('node:test');
const assert = require('node:assert');
const payloadGuard = require('../index');

function mockResponse() {
  const res = {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.body = data;
      return this;
    }
  };
  return res;
}

test('middleware - sanitizes req.body, req.query and req.params in-place', () => {
  const mw = payloadGuard();
  const req = {
    body: { user: '  alex  ', filter: { $where: 'evil()' } },
    query: { 'search.q': 'node', role: 'admin ' },
    params: { id: ' 123 ' }
  };
  const res = mockResponse();
  let nextCalled = false;

  mw(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, true);
  assert.strictEqual(req.body.user, 'alex');
  assert.strictEqual(req.body.filter.$where, undefined);
  assert.strictEqual(req.query['search.q'], undefined);
  assert.strictEqual(req.query.role, 'admin');
  assert.strictEqual(req.params.id, '123');
});

test('middleware - blocks request with 400 when block option is true', () => {
  const mw = payloadGuard({ block: true });
  const req = {
    body: { $gt: '' }
  };
  const res = mockResponse();
  let nextCalled = false;

  mw(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, false);
  assert.strictEqual(res.statusCode, 400);
  assert.strictEqual(res.body.error, 'Bad Request');
  assert.strictEqual(res.body.violations.length, 1);
});

test('middleware - triggers custom onViolation handler', () => {
  let capturedViolations = null;
  const mw = payloadGuard({
    onViolation: (req, res, next, violations) => {
      capturedViolations = violations;
      res.status(422).json({ count: violations.length });
    }
  });

  const req = {
    query: { $ne: null }
  };
  const res = mockResponse();

  mw(req, res, () => {});

  assert.strictEqual(res.statusCode, 422);
  assert.strictEqual(capturedViolations.length, 1);
  assert.strictEqual(capturedViolations[0].target, 'query');
});

test('middleware - safely ignores empty or missing request objects', () => {
  const mw = payloadGuard();
  const req = {};
  const res = mockResponse();
  let nextCalled = false;

  mw(req, res, () => {
    nextCalled = true;
  });

  assert.strictEqual(nextCalled, true);
});
