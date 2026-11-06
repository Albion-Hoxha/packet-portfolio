// Game logic only, no DOM. Every IP below is from a reserved documentation range,
// so the simulated data never names a real host.
import { dissect, parseCidr } from './lab.js';

export const MAX_INPUT = 200;
export const TOTAL_LEVELS = 5;

const buildLog = () => {
  const lines = [];
  const clients = ['192.0.2.14', '192.0.2.31', '192.0.2.58', '198.51.100.23'];
  const scannedPorts = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 445, 993, 3306, 3389, 5432, 8080];
  let seconds = 0;
  const add = (action, ip, port) => {
    seconds += 7;
    const time = `09:${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
    lines.push(`${time} ${action.padEnd(5)} TCP ${ip} -> 198.51.100.10:${port}`);
  };
  scannedPorts.forEach((port, i) => {
    add('ALLOW', clients[i % clients.length], 443);
    add('DENY', '203.0.113.77', port);
    if (i === 4) add('DENY', '203.0.113.12', 23);
    if (i === 11) add('DENY', '203.0.113.40', 22);
  });
  return lines.join('\n');
};

const FILES = new Map([
  ['readme.txt', 'Five flags are hidden here. Solve them in order.\nEverything is simulated and runs in your browser.\nType "hint" if you get stuck.'],
  ['note.b64', 'RW5jb2RpbmcgaXMgbm90IGVuY3J5cHRpb24uIEFueW9uZSBjYW4gcmV2ZXJzZSBpdC4KZmxhZ3tiYXNlNjRfaXNfbm90X2VuY3J5cHRpb259Cg=='],
  ['access.log', buildLog()],
  ['capture.hex', '450000541a2b400040013432c000020ec633640a\n4500003cc0de400034061f53cb00714dc633640a\n4500004c7f314000801126e7c6336417c633640a'],
]);

const LEVELS = [
  {
    hash: 'd7ba614676b457e3e6c432df3d5965368400fd07723d23b85ddbbba4e8e781c3',
    intro: 'Level 1: Encoding. Something in note.b64 looks scrambled.',
    hint: 'The file name is a clue. Try: base64 -d note.b64',
    reward: ['Skill unlocked: knowing encoding from encryption. Base64 hides nothing.'],
  },
  {
    hash: '338836a04d39ec0c4f2e8bf9f9a83db72fadb98e0df8a091f3b1f8844433edf6',
    intro: 'Level 2: Network. This site says more than its page shows.',
    hint: 'Look at the HTTP response headers. Try: curl -I /',
    reward: ['Project unlocked: AWS Amplify Hosting sent you that header, along with the', 'security headers next to it. They are defined in one config file in the repo.'],
  },
  {
    hash: '1a0b1c852206ca0044681fdc3004a86fb339acfe06312cc4932abfbf126877e8',
    intro: 'Level 3: Log analysis. One source in access.log is scanning ports.\nThe flag is flag{<that IP>}.',
    hint: 'Filter the blocked traffic: grep DENY access.log. Which IP tries many ports?',
    reward: ['Skill unlocked: reading logs. One source touching many ports stands out fast.'],
  },
  {
    hash: '96ffa3c1268c9ff6e42b60f704061b72d0e2b4d2eb4fada6ef1bb101802fecbf',
    intro: 'Level 4: Subnetting. A host sits at 198.51.100.77/26.\nThe flag is flag{<its broadcast address>}.',
    hint: 'Try: subnet 198.51.100.77/26. The Subnet Lab on the page shows the same thing bit by bit.',
    reward: ['Tool unlocked: the Subnet Lab on this page works for any IPv4 network.'],
  },
  {
    hash: '6163e2e3feb1588152eb658a4138b4b60329add73ef87def09d703cb02acac03',
    intro: 'Level 5: Packet analysis. capture.hex holds three IPv4 headers, and one has a corrupted checksum.\nThe flag is flag{<its identification field>}, written like flag{0x1234}.',
    hint: 'Try: dissect capture.hex. Which checksum fails?',
    reward: [
      'That is all five flags. Thanks for playing.',
      { text: 'Connect with me on LinkedIn', href: 'https://www.linkedin.com/in/albion-hoxha/' },
    ],
  },
];

const HELP = [
  'help                 show this list',
  'ls                   list files',
  'cat <file>           print a file',
  'base64 -d <file>     decode a file',
  'grep <text> <file>   show matching lines',
  'curl -I /            show this site\'s real response headers',
  'subnet <ip/prefix>   work out a subnet',
  'dissect <file>       read IPv4 headers from a hex file',
  'submit <flag>        submit a flag',
  'hint                 get a nudge',
  'progress             show flags found',
  'clear                clear the screen',
  'exit                 close the terminal',
];

const sha256 = async (text) => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
};

const readFile = (name) => (FILES.has(name) ? FILES.get(name) : null);

export function createGame(fetchHeaders) {
  let level = 0;
  const done = () => level >= TOTAL_LEVELS;

  const curl = async (args) => {
    if (args.join(' ') !== '-I /') return ['Only this form works here: curl -I /'];
    try {
      const { status, headers } = await fetchHeaders();
      const lines = [`HTTP ${status}`, ...headers.map(([name, value]) => `${name}: ${value}`)];
      if (!headers.some(([name]) => name === 'x-flag')) lines.push('', 'No x-flag header on this response.');
      return lines;
    } catch {
      return ['Network error. Try again.'];
    }
  };

  const submit = async (args) => {
    if (args.length !== 1) return ['Usage: submit flag{...}'];
    if (done()) return ['You already have all the flags.'];
    if (!globalThis.crypto?.subtle) return ['Checking flags needs HTTPS.'];
    if ((await sha256(args[0])) !== LEVELS[level].hash) return ['Not this level\'s flag. Keep looking.'];
    const { reward } = LEVELS[level];
    level += 1;
    return [`Correct! Flag ${level}/${TOTAL_LEVELS}.`, ...reward, ...(done() ? [] : ['', LEVELS[level].intro])];
  };

  const decode = (args) => {
    if (args.length !== 2 || args[0] !== '-d') return ['Usage: base64 -d <file>'];
    const content = readFile(args[1]);
    if (content === null) return [`No such file: ${args[1]}`];
    try {
      return atob(content).trimEnd().split('\n');
    } catch {
      return ['That file is not valid base64.'];
    }
  };

  const grep = (args) => {
    if (args.length !== 2) return ['Usage: grep <text> <file>'];
    const content = readFile(args[1]);
    if (content === null) return [`No such file: ${args[1]}`];
    const matches = content.split('\n').filter((line) => line.includes(args[0]));
    return matches.length ? matches : ['No matches.'];
  };

  const subnetInfo = (args) => {
    if (args.length !== 1) return ['Usage: subnet <ip/prefix>'];
    const result = parseCidr(args[0]);
    if (result.error) return [result.error];
    return [
      `Network    ${result.network}/${result.prefix}`,
      `Mask       ${result.mask}`,
      `Broadcast  ${result.broadcast}`,
      `Hosts      ${result.firstHost} to ${result.lastHost} (${result.hosts})`,
    ];
  };

  const dissectFile = (args) => {
    if (args.length !== 1) return ['Usage: dissect <file>'];
    const content = readFile(args[0]);
    if (content === null) return [`No such file: ${args[0]}`];
    return content.split('\n').map((line, i) => {
      const packet = dissect(line);
      if (packet.error) return `${i + 1}: ${packet.error}`;
      return `${i + 1}: ${packet.source} -> ${packet.destination}  ${packet.protocol}  TTL ${packet.ttl}  ID ${packet.id}  checksum ${packet.checksumValid ? 'valid' : 'INVALID'}`;
    });
  };

  const dispatch = async (command, args) => {
    switch (command) {
      case 'help': return HELP;
      case 'ls': return [...FILES.keys()];
      case 'cat': {
        if (args.length !== 1) return ['Usage: cat <file>'];
        const content = readFile(args[0]);
        return content === null ? [`No such file: ${args[0]}`] : content.split('\n');
      }
      case 'base64': return decode(args);
      case 'grep': return grep(args);
      case 'curl': return curl(args);
      case 'subnet': return subnetInfo(args);
      case 'dissect': return dissectFile(args);
      case 'submit': return submit(args);
      case 'hint': return [done() ? 'Nothing left to find.' : LEVELS[level].hint];
      case 'progress': return [`Flags: ${level}/${TOTAL_LEVELS}`];
      default: return [`Command not found: ${command}. Type "help".`];
    }
  };

  return {
    get level() { return level; },
    intro: () => ['Mini-CTF. Five flags, all simulated, all in your browser.', 'Type "help" for commands. Run one command at a time.', '', LEVELS[0].intro],
    async run(input) {
      if (input.length > MAX_INPUT) return { lines: [`Input is limited to ${MAX_INPUT} characters.`] };
      const [command, ...args] = input.trim().split(/\s+/);
      if (!command) return { lines: [] };
      if (command === 'clear') return { lines: [], action: 'clear' };
      if (command === 'exit') return { lines: [], action: 'close' };
      // Players often paste a flag without the submit command.
      if (command.startsWith('flag{')) return { lines: await dispatch('submit', [command, ...args]) };
      return { lines: await dispatch(command, args) };
    },
  };
}
