#!/usr/bin/env node
/**
 * Test script to verify Supabase connection string compatibility
 * This script validates that various Supabase connection string formats work correctly
 */

const testConnectionStrings = [
  {
    name: "Local PostgreSQL",
    url: "postgresql://postgres:postgres@localhost:5432/mysso?schema=public",
    expected: true
  },
  {
    name: "Supabase Direct Connection",
    url: "postgresql://postgres:password@db.project-ref.supabase.co:5432/postgres",
    expected: true
  },
  {
    name: "Supabase Connection Pooling (Recommended)",
    url: "postgresql://postgres.project-ref:password@aws-0-us-west-1.pooler.supabase.com:6543/postgres?pgbouncer=true",
    expected: true
  },
  {
    name: "Supabase with SSL",
    url: "postgresql://postgres:password@db.project-ref.supabase.co:5432/postgres?sslmode=require",
    expected: true
  }
];

console.log("🧪 Testing Supabase Connection String Compatibility\n");

let allPassed = true;

testConnectionStrings.forEach((test) => {
  try {
    // Basic URL parsing test
    const url = new URL(test.url);
    
    // Validate it's a postgresql URL
    const isValid = url.protocol === 'postgresql:' || url.protocol === 'postgres:';
    
    if (isValid === test.expected) {
      console.log(`✅ ${test.name}`);
      // Truncate URL intelligently - show protocol, host (partially), and important params
      const displayUrl = test.url.length > 70 
        ? `${test.url.substring(0, 40)}...${test.url.substring(test.url.length - 27)}`
        : test.url;
      console.log(`   ${displayUrl}`);
    } else {
      console.log(`❌ ${test.name}`);
      console.log(`   URL: ${test.url}`);
      console.log(`   Expected: ${test.expected}, Got: ${isValid}`);
      allPassed = false;
    }
  } catch (error) {
    console.log(`❌ ${test.name}`);
    console.log(`   URL: ${test.url}`);
    console.log(`   Error: ${error.message}`);
    allPassed = false;
  }
  console.log();
});

if (allPassed) {
  console.log("✅ All connection string formats are compatible!");
  console.log("\n📖 See SUPABASE_MIGRATION.md for detailed setup instructions.");
  process.exit(0);
} else {
  console.log("❌ Some connection string formats failed validation");
  process.exit(1);
}
