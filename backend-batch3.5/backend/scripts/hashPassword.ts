// One-time developer utility — NOT part of the running server. Run this
// once to generate ANALYST_PASSWORD_HASH for your .env file.
//
// Usage: npm run hash:password -- "your-chosen-password"

import { hashPassword } from "../src/utils/password";

const password = process.argv[2];

if (!password) {
  console.error('Usage: npm run hash:password -- "your-chosen-password"');
  process.exit(1);
}

const hash = hashPassword(password);
console.log("\nPaste this into .env:\n");
console.log(`ANALYST_PASSWORD_HASH=${hash}\n`);
