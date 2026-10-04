import 'dotenv/config';
import { createApp } from './app.js';
import { migrate } from './migrate.js';

const port = Number(process.env.PORT) || 5050;

await migrate();
createApp().listen(port, () => {
  console.log(`api listening on http://localhost:${port}`);
});
