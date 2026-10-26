const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function isPlainObject(val) {
  if (!val || typeof val !== 'object') return false;
  const proto = Object.getPrototypeOf(val);
  return proto === null || proto === Object.prototype;
}

function isNoSqlKey(key) {
  return key.startsWith('$') || key.includes('.');
}

function stripHtml(str) {
  return str.replace(/<[^>]*>?/gm, '');
}

module.exports = {
  DANGEROUS_KEYS,
  isPlainObject,
  isNoSqlKey,
  stripHtml
};
