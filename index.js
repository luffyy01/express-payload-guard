const payloadGuard = require('./lib/guard');
const { sanitize } = require('./lib/sanitize');

payloadGuard.guard = payloadGuard;
payloadGuard.sanitize = sanitize;
payloadGuard.payloadGuard = payloadGuard;

module.exports = payloadGuard;
