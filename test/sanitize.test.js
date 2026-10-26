const test = require('node:test');
const assert = require('node:assert');
const { sanitize } = require('../index');

test('sanitize - strips nosql operator keys by default', () => {
  const dirty = {
    username: 'admin',
    password: { $ne: null },
    'profile.bio': 'dev'
  };

  const res = sanitize(dirty);
  assert.strictEqual(res.isValid, false);
  assert.strictEqual(res.data.username, 'admin');
  assert.strictEqual(res.data.password.$ne, undefined);
  assert.strictEqual(res.data['profile.bio'], undefined);
  assert.strictEqual(res.violations.length, 2);
});

test('sanitize - blocks prototype pollution keys', () => {
  const dirty = JSON.parse('{"name":"test","__proto__":{"polluted":true}}');
  const res = sanitize(dirty);

  assert.strictEqual(res.isValid, false);
  assert.strictEqual(res.data.name, 'test');
  assert.strictEqual(Object.prototype.polluted, undefined);
  assert.strictEqual(res.violations[0].type, 'PROTOTYPE_POLLUTION');
});

test('sanitize - trims strings by default', () => {
  const dirty = {
    email: '  user@example.com   ',
    tags: ['  node ', 'js  ']
  };

  const res = sanitize(dirty);
  assert.strictEqual(res.data.email, 'user@example.com');
  assert.deepStrictEqual(res.data.tags, ['node', 'js']);
  assert.strictEqual(res.isValid, true);
});

test('sanitize - strips html when xss enabled', () => {
  const dirty = {
    comment: 'Hello <script>alert(1)</script>world!'
  };

  const res = sanitize(dirty, { xss: true });
  assert.strictEqual(res.data.comment, 'Hello alert(1)world!');
  assert.strictEqual(res.isValid, false);
  assert.strictEqual(res.violations[0].type, 'XSS_DETECTED');
});

test('sanitize - respects key whitelist', () => {
  const dirty = {
    $allowedField: 'safe',
    $badField: 'drop'
  };

  const res = sanitize(dirty, { whitelist: ['$allowedField'] });
  assert.strictEqual(res.data.$allowedField, 'safe');
  assert.strictEqual(res.data.$badField, undefined);
  assert.strictEqual(res.violations.length, 1);
});

test('sanitize - handles maxDepth protection', () => {
  const deeplyNested = { a: { b: { c: { d: { e: 'too deep' } } } } };
  const res = sanitize(deeplyNested, { maxDepth: 3 });

  assert.strictEqual(res.isValid, false);
  assert.strictEqual(res.violations.some(v => v.type === 'MAX_DEPTH_EXCEEDED'), true);
});

test('sanitize - preserves primitives safely', () => {
  const mixed = {
    num: 42,
    bool: true,
    n: null,
    u: undefined
  };

  const res = sanitize(mixed);
  assert.strictEqual(res.data.num, 42);
  assert.strictEqual(res.data.bool, true);
  assert.strictEqual(res.data.n, null);
  assert.strictEqual(res.data.u, undefined);
  assert.strictEqual(res.isValid, true);
});
