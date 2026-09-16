import { readFile } from 'node:fs/promises';
import { calculateCost } from '../src/cost.js';
try {
  const args = process.argv.slice(2);
  if (args.length !== 2) throw new Error('Usage: npm run cost -- DIAGNOSTICS.json prices.json');
  const [diagnostics, prices] = await Promise.all(args.map(async path => JSON.parse(await readFile(path, 'utf8'))));
  console.log(JSON.stringify(calculateCost(diagnostics, prices), null, 2));
} catch { console.error('Cost calculation failed. Supply a valid diagnostics JSON file and nonnegative prices; see docs/OPERATIONS.md.'); process.exitCode = 1; }
