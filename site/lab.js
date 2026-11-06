// Network tool logic, no DOM. Used by the Lab section and by the CTF console.

const MAX_HEADER_BYTES = 60;
const PROTOCOLS = new Map([[1, 'ICMP'], [2, 'IGMP'], [6, 'TCP'], [17, 'UDP'], [41, 'IPv6'], [47, 'GRE'], [50, 'ESP'], [89, 'OSPF']]);

const toDotted = (n) => [24, 16, 8, 0].map((shift) => (n >>> shift) & 255).join('.');

const parseIPv4 = (text) => {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) return null;
  const octets = text.split('.').map(Number);
  if (octets.some((octet) => octet > 255)) return null;
  return octets.reduce((n, octet) => n * 256 + octet, 0);
};

export function subnet(address, prefix) {
  const ip = parseIPv4(address.trim());
  if (ip === null) return { error: 'Enter an IPv4 address such as 192.0.2.77.' };
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return { error: 'The prefix must be between 0 and 32.' };

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  const pointToPoint = prefix >= 31; // RFC 3021: /31 and /32 have no separate network or broadcast address.

  return {
    prefix,
    bits: ip.toString(2).padStart(32, '0'),
    network: toDotted(network),
    broadcast: pointToPoint ? 'None' : toDotted(broadcast),
    firstHost: toDotted(pointToPoint ? network : network + 1),
    lastHost: toDotted(pointToPoint ? broadcast : broadcast - 1),
    mask: toDotted(mask),
    wildcard: toDotted(~mask >>> 0),
    hosts: pointToPoint ? 2 ** (32 - prefix) : 2 ** (32 - prefix) - 2,
  };
}

export function parseCidr(text) {
  const match = /^([\d.]+)\/(\d{1,2})$/.exec(text.trim());
  return match ? subnet(match[1], Number(match[2])) : { error: 'Use the form 192.0.2.77/26.' };
}

const checksum = (bytes) => {
  let total = 0;
  for (let i = 0; i < bytes.length; i += 2) total += bytes[i] * 256 + bytes[i + 1];
  while (total > 0xffff) total = (total & 0xffff) + Math.floor(total / 0x10000);
  return ~total & 0xffff;
};

const hex16 = (n) => `0x${n.toString(16).padStart(4, '0')}`;

export function dissect(text) {
  const hex = text.replace(/0x|[\s:]/gi, '').toLowerCase();
  if (!hex) return { error: 'Paste an IPv4 header as hex.' };
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2) return { error: 'That is not valid hex.' };
  if (hex.length / 2 < 20) return { error: 'An IPv4 header is at least 20 bytes.' };
  if (hex.length / 2 > MAX_HEADER_BYTES) return { error: `An IPv4 header is at most ${MAX_HEADER_BYTES} bytes.` };

  const bytes = Uint8Array.from(hex.match(/../g), (pair) => parseInt(pair, 16));
  const version = bytes[0] >> 4;
  const ihl = bytes[0] & 15;
  if (version !== 4) return { error: `This is version ${version}, not IPv4.` };
  if (ihl < 5 || ihl * 4 > bytes.length) return { error: 'The header length field does not match the data.' };

  const word = (i) => bytes[i] * 256 + bytes[i + 1];
  const address = (i) => toDotted(word(i) * 0x10000 + word(i + 2));
  const flagBits = bytes[6] >> 5;
  const protocol = PROTOCOLS.get(bytes[9]) ?? 'Other';
  const header = bytes.slice(0, ihl * 4);
  const checksumValid = checksum(header) === 0;
  const flags = [flagBits & 2 ? 'DF' : '', flagBits & 1 ? 'MF' : ''].filter(Boolean).join(' ') || 'None';

  return {
    id: hex16(word(4)),
    source: address(12),
    destination: address(16),
    protocol,
    ttl: bytes[8],
    checksumValid,
    fields: [
      { name: 'Version', width: 4, value: String(version) },
      { name: 'IHL', width: 4, value: `${ihl * 4} bytes` },
      { name: 'DSCP', width: 6, value: String(bytes[1] >> 2) },
      { name: 'ECN', width: 2, value: String(bytes[1] & 3) },
      { name: 'Total length', width: 16, value: `${word(2)} bytes` },
      { name: 'Identification', width: 16, value: hex16(word(4)) },
      { name: 'Flags', width: 3, value: flags },
      { name: 'Fragment offset', width: 13, value: String(word(6) & 0x1fff) },
      { name: 'TTL', width: 8, value: String(bytes[8]) },
      { name: 'Protocol', width: 8, value: `${bytes[9]} (${protocol})` },
      { name: 'Checksum', width: 16, value: `${hex16(word(10))} ${checksumValid ? 'valid' : 'INVALID'}`, bad: !checksumValid },
      { name: 'Source', width: 32, value: address(12) },
      { name: 'Destination', width: 32, value: address(16) },
    ],
  };
}

// shortcut: common edge locations only, unknown ones show their airport code. Add more if visitors see codes.
const EDGE_CITIES = new Map([
  ['AMS', 'Amsterdam'], ['ARN', 'Stockholm'], ['ATH', 'Athens'], ['BOM', 'Mumbai'], ['CDG', 'Paris'], ['DEL', 'New Delhi'],
  ['FCO', 'Rome'], ['FRA', 'Frankfurt'], ['GRU', 'Sao Paulo'], ['IAD', 'Virginia'], ['JFK', 'New York'], ['LHR', 'London'],
  ['MAD', 'Madrid'], ['MUC', 'Munich'], ['MXP', 'Milan'], ['NRT', 'Tokyo'], ['OTP', 'Bucharest'], ['SEA', 'Seattle'],
  ['SFO', 'San Francisco'], ['SIN', 'Singapore'], ['SOF', 'Sofia'], ['SYD', 'Sydney'], ['VIE', 'Vienna'], ['WAW', 'Warsaw'], ['ZRH', 'Zurich'],
]);

export function traceEdge(entries) {
  const headers = new Map(entries.map(([name, value]) => [name.toLowerCase(), value]));
  const pop = headers.get('x-amz-cf-pop');
  if (!pop) return { onAws: false };
  const code = pop.slice(0, 3).toUpperCase();
  return {
    onAws: true,
    pop,
    city: EDGE_CITIES.get(code) ?? code,
    cacheHit: /hit/i.test(headers.get('x-cache') ?? ''),
    origin: headers.get('server') ?? 'Unknown',
  };
}

const SECURITY_CHECKS = [
  {
    name: 'Content-Security-Policy',
    why: 'Limits where scripts can load from, which blocks most cross-site scripting.',
    pass: (h) => Boolean(h.get('content-security-policy')) && !/unsafe-inline|unsafe-eval/.test(h.get('content-security-policy')),
  },
  {
    name: 'Strict-Transport-Security',
    why: 'Tells browsers to use HTTPS only, so a connection cannot be downgraded.',
    pass: (h) => Number(/max-age=(\d+)/.exec(h.get('strict-transport-security') ?? '')?.[1] ?? 0) >= 15552000,
  },
  {
    name: 'X-Frame-Options',
    why: 'Stops other sites from framing this page for clickjacking.',
    pass: (h) => /^(deny|sameorigin)$/i.test(h.get('x-frame-options') ?? ''),
  },
  {
    name: 'X-Content-Type-Options',
    why: 'Stops browsers from guessing file types and running the wrong thing.',
    pass: (h) => (h.get('x-content-type-options') ?? '').toLowerCase() === 'nosniff',
  },
  {
    name: 'Referrer-Policy',
    why: 'Keeps full page addresses from leaking to other sites.',
    pass: (h) => /^(no-referrer|same-origin|strict-origin|strict-origin-when-cross-origin)$/.test(h.get('referrer-policy') ?? ''),
  },
];

export function gradeHeaders(entries) {
  const headers = new Map(entries.map(([name, value]) => [name.toLowerCase(), value]));
  return SECURITY_CHECKS.map(({ name, why, pass }) => ({ name, why, passed: pass(headers) }));
}
