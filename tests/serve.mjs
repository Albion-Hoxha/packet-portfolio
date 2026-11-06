// Local preview that sends the same headers Amplify will, so level 2 and the CSP can be tested.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readHeaders } from './headers.mjs';

const root = fileURLToPath(new URL('../site', import.meta.url));
const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' };
const headers = readHeaders();
const port = Number(process.argv[2] ?? 4173);

createServer(async (req, res) => {
  const path = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  const file = normalize(join(root, path === '/' ? 'index.html' : path));
  try {
    if (!file.startsWith(root + sep)) throw new Error('outside site');
    const body = await readFile(file);
    res.writeHead(200, { ...headers, 'Content-Type': types[extname(file)] ?? 'application/octet-stream' });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch {
    res.writeHead(404, headers);
    res.end('Not found');
  }
}).listen(port, () => console.log(`http://localhost:${port}`));
