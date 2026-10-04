import { readFile } from 'node:fs/promises';
import { pool } from './db.js';

export async function migrate() {
  const sql = await readFile(new URL('./schema.sql', import.meta.url), 'utf8');
  await pool.query(sql);
}

// allow `npm run migrate`
if (process.argv[1]?.endsWith('migrate.js')) {
  migrate()
    .then(() => {
      console.log('schema ready');
      return pool.end();
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
