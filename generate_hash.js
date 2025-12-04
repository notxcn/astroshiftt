const bcrypt = require('bcryptjs');

const password = process.argv[2];

if (!password) {
    console.log('Please provide a password as an argument.');
    console.log('Usage: node generate_hash.js "your_password_here"');
    process.exit(1);
}

const salt = bcrypt.genSaltSync(10);
const hash = bcrypt.hashSync(password, salt);

console.log('\nPassword:', password);
console.log('Hash:', hash);
console.log('\nCopy the "Hash" value above and use it for ADMIN_PASSWORD_HASH in Railway.');
