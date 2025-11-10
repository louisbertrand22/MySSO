#!/usr/bin/env node

/**
 * Test script for logout functionality
 * This script demonstrates the logout endpoint with cookies and session revocation
 * 
 * Note: This is a manual test script. For proper testing, set up a database 
 * and run the server with: npm run dev
 */

const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

console.log('╔════════════════════════════════════════════════════════════╗');
console.log('║          MySSO Logout Functionality Test Guide            ║');
console.log('╚════════════════════════════════════════════════════════════╝\n');

console.log('This script helps you test the logout functionality manually.\n');

console.log('Prerequisites:');
console.log('1. Set up a PostgreSQL database');
console.log('2. Configure DATABASE_URL in .env file');
console.log('3. Run: npx prisma migrate dev');
console.log('4. Start the server: npm run dev\n');

console.log('Test Steps:\n');

console.log('Step 1: Register a user');
console.log('  curl -X POST http://localhost:3000/auth/register \\');
console.log('    -H "Content-Type: application/json" \\');
console.log('    -d \'{"email":"test@example.com","password":"password123"}\'\n');

console.log('Step 2: Login and get tokens');
console.log('  curl -X POST http://localhost:3000/auth/login \\');
console.log('    -H "Content-Type: application/json" \\');
console.log('    -d \'{"email":"test@example.com","password":"password123"}\' \\');
console.log('    -c cookies.txt\n');
console.log('  (Save the refreshToken from the response)\n');

console.log('Step 3: Test single device logout');
console.log('  curl -X POST http://localhost:3000/auth/logout \\');
console.log('    -H "Content-Type: application/json" \\');
console.log('    -b cookies.txt \\');
console.log('    -d \'{"refreshToken":"YOUR_REFRESH_TOKEN"}\'\n');

console.log('Step 4: Verify cookie is cleared');
console.log('  curl -X POST http://localhost:3000/auth/refresh \\');
console.log('    -b cookies.txt \\');
console.log('    -v\n');
console.log('  (Should fail with 400 or 403)\n');

console.log('Step 5: Test logout from all devices');
console.log('  a) Login again to get a new token');
console.log('  b) Run logout with "all" flag:');
console.log('     curl -X POST http://localhost:3000/auth/logout \\');
console.log('       -H "Content-Type: application/json" \\');
console.log('       -b cookies.txt \\');
console.log('       -d \'{"refreshToken":"YOUR_REFRESH_TOKEN","all":true}\'\n');

console.log('Step 6: Check security logs');
console.log('  Review server console output for [SECURITY] log entries\n');

console.log('Expected Results:');
console.log('✓ Cookies are cleared after logout');
console.log('✓ Refresh tokens are deleted from database');
console.log('✓ Sessions are marked as revoked (revokedAt is set)');
console.log('✓ Security logs show TOKEN_REVOCATION and LOGOUT events');
console.log('✓ Revoked tokens cannot be used to refresh access tokens\n');

console.log('Features Implemented:');
console.log('✓ POST /auth/logout endpoint');
console.log('✓ HttpOnly cookie support for refresh tokens');
console.log('✓ Cookie deletion on logout');
console.log('✓ Session tracking in database');
console.log('✓ Session revocation with revokedAt field');
console.log('✓ Logout from all devices (deleteMany)');
console.log('✓ Security logging for audit trail\n');

rl.question('Press Enter to exit...', () => {
  rl.close();
});
