/**
 * Migration Check Script
 *
 * This script checks for pending migrations and optionally applies them.
 * Run before development to ensure your database schema is up to date.
 *
 * Usage:
 *   npx tsx scripts/check-migrations.ts        # Check only
 *   npx tsx scripts/check-migrations.ts --run  # Check and run pending migrations
 */

// import { AppDataSource } from '../src/config/data.source';
import { AppDataSource } from '@config/data.source';
async function checkMigrations() {
  const shouldRun = process.argv.includes('--run');

  try {
    // Initialize the data source
    await AppDataSource.initialize();
    console.log('✅ Database connection established\n');

    // Get pending migrations
    const pendingMigrations = await AppDataSource.showMigrations();

    if (pendingMigrations) {
      console.log('⚠️  There are pending migrations!\n');

      // Get list of all migrations and executed ones
      const allMigrations = AppDataSource.migrations;
      const executedMigrations = await AppDataSource.query(
        `SELECT * FROM "migrations" ORDER BY "timestamp" DESC`
      ).catch(() => []);

      const executedNames = new Set(executedMigrations.map((m: any) => m.name));

      console.log('📋 Migration Status:');
      console.log('─'.repeat(60));

      for (const migration of allMigrations) {
        const name = migration.name;
        const status = executedNames.has(name) ? '✅ Applied' : '⏳ Pending';
        console.log(`  ${status}: ${name}`);
      }

      console.log('─'.repeat(60));

      if (shouldRun) {
        console.log('\n🚀 Running pending migrations...\n');
        await AppDataSource.runMigrations();
        console.log('\n✅ All migrations applied successfully!');
      } else {
        console.log('\n💡 Run with --run flag to apply pending migrations:');
        console.log('   npm run migration:check:run\n');
      }
    } else {
      console.log('✅ Database schema is up to date. No pending migrations.\n');
    }
  } catch (error: unknown) {
    const message = formatMigrationError(error);
    if (message.includes('migrations')) {
      console.log(
        '📋 No migrations table found. This might be a fresh database.'
      );
      console.log('   Run migrations to set up the schema.\n');
    } else {
      console.error('❌ Error checking migrations:', message);
      process.exit(1);
    }
  } finally {
    if (AppDataSource.isInitialized) {
      await AppDataSource.destroy();
    }
  }
}

function formatMigrationError(error: unknown): string {
  if (error instanceof AggregateError) {
    const nested = error.errors
      .map((item) => (item instanceof Error ? item.message : String(item)))
      .filter(Boolean);
    if (nested.length > 0) return nested.join('; ');
  }

  if (error instanceof Error && error.message) return error.message;
  return String(error);
}

checkMigrations();
