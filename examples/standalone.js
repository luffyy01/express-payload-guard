const { sanitize } = require('../index');

const rawUserInput = {
  name: '   Sarah Connor   ',
  email: 'sarah@resistance.org',
  query: {
    $where: 'this.role === "admin"',
    status: 'active'
  },
  bio: 'Developer <script>stealCookies()</script>'
};

const result = sanitize(rawUserInput, { xss: true });

console.log('Is valid:', result.isValid);
console.log('Cleaned payload:', result.data);
console.log('Violations caught:', result.violations);
