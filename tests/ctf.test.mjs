import test from 'node:test';
import assert from 'node:assert/strict';
import { createGame, MAX_INPUT } from '../site/ctf.js';
import { readHeaders } from './headers.mjs';

const flagHeader = readHeaders()['X-Flag'];
const fetchHeaders = async () => ({ status: 200, headers: [['x-flag', flagHeader]] });
const out = async (game, input) => (await game.run(input)).lines.map((l) => l.text ?? l).join('\n');
const findFlag = (text) => text.match(/flag\{[^}<]+\}/)[0];

test('all five levels solve using only in-game commands', async () => {
  const game = createGame(fetchHeaders);

  await out(game, `submit ${findFlag(await out(game, 'base64 -d note.b64'))}`);
  assert.equal(game.level, 1);

  await out(game, `submit ${findFlag(await out(game, 'curl -I /'))}`);
  assert.equal(game.level, 2);

  const denied = (await out(game, 'grep DENY access.log')).split('\n');
  const counts = {};
  for (const line of denied) {
    const ip = line.match(/TCP (\S+)/)[1];
    counts[ip] = (counts[ip] ?? 0) + 1;
  }
  const [scanner] = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
  await out(game, `submit flag{${scanner}}`);
  assert.equal(game.level, 3);

  const broadcast = (await out(game, 'subnet 198.51.100.77/26')).match(/Broadcast\s+(\S+)/)[1];
  await out(game, `submit flag{${broadcast}}`);
  assert.equal(game.level, 4);

  const invalid = (await out(game, 'dissect capture.hex')).split('\n').filter((line) => line.includes('INVALID'));
  assert.equal(invalid.length, 1);
  const final = await game.run(`submit flag{${invalid[0].match(/ID (\S+)/)[1]}}`);
  assert.equal(game.level, 5);
  assert.ok(final.lines.some((l) => l.href?.startsWith('https://www.linkedin.com/')));
  assert.match(await out(game, 'submit flag{x}'), /already have/);
  assert.match(await out(game, 'hint'), /Nothing left/);
});

test('wrong and out-of-order flags change nothing', async () => {
  const game = createGame(fetchHeaders);
  assert.match(await out(game, 'submit flag{nope}'), /Not this level/);
  assert.match(await out(game, `submit ${flagHeader}`), /Not this level/);
  assert.equal(game.level, 0);
});

test('log uses only reserved documentation addresses and has one clear scanner', async () => {
  const game = createGame(fetchHeaders);
  const log = await out(game, 'cat access.log');
  for (const ip of log.match(/\d+\.\d+\.\d+\.\d+/g)) {
    assert.match(ip, /^(192\.0\.2|198\.51\.100|203\.0\.113)\./);
  }
  assert.equal(log.split('\n').filter((l) => l.includes('203.0.113.77')).length, 16);
});

test('bad input gets a safe answer', async () => {
  const game = createGame(fetchHeaders);
  assert.match(await out(game, 'rm -rf /'), /Command not found/);
  assert.match(await out(game, 'constructor'), /Command not found/);
  assert.match(await out(game, 'cat __proto__'), /No such file/);
  assert.match(await out(game, 'cat ../../etc/passwd'), /No such file/);
  assert.match(await out(game, 'base64 -d access.log'), /not valid base64/);
  assert.match(await out(game, 'grep x __proto__'), /No such file/);
  assert.match(await out(game, 'dissect __proto__'), /No such file/);
  assert.match(await out(game, 'subnet 999.1.1.1/24'), /Enter an IPv4/);
  assert.match(await out(game, 'subnet nonsense'), /Use the form/);
  assert.match(await out(game, 'curl https://example.com'), /Only this form/);
  assert.match(await out(game, 'a'.repeat(MAX_INPUT + 1)), /limited/);
  assert.equal(await out(game, '   '), '');
});

test('a flag typed on its own counts as a submit', async () => {
  const game = createGame(fetchHeaders);
  assert.match(await out(game, 'flag{nope}'), /Not this level/);
  assert.match(await out(game, 'flag{base64_is_not_encryption}'), /Correct/);
  assert.equal(game.level, 1);
});

test('clear and exit report an action', async () => {
  const game = createGame(fetchHeaders);
  assert.equal((await game.run('clear')).action, 'clear');
  assert.equal((await game.run('exit')).action, 'close');
});

test('curl handles a missing header and a network failure', async () => {
  const noFlag = createGame(async () => ({ status: 200, headers: [] }));
  assert.match(await out(noFlag, 'curl -I /'), /No x-flag header/);
  const offline = createGame(async () => { throw new Error('down'); });
  assert.match(await out(offline, 'curl -I /'), /Network error/);
});
