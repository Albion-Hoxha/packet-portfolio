import { createGame, MAX_INPUT, TOTAL_LEVELS } from './ctf.js';
import { initLab } from './lab-ui.js';

const fetchHeaders = async () => {
  const response = await fetch('/', { method: 'HEAD', cache: 'no-store' });
  return { status: response.status, headers: [...response.headers] };
};

const game = createGame(fetchHeaders);
const dialog = document.querySelector('.console');
const output = document.querySelector('.output');
const form = document.querySelector('.prompt');
const input = document.querySelector('#cmd');
input.maxLength = MAX_INPUT;

const print = (line, className) => {
  const row = document.createElement('p');
  if (className) row.className = className;
  if (line.href) {
    const link = document.createElement('a');
    link.href = line.href;
    link.rel = 'noopener noreferrer';
    link.target = '_blank';
    link.textContent = line.text;
    row.append(link);
  } else {
    row.textContent = line;
  }
  output.append(row);
};

const showFlags = () => {
  document.querySelectorAll('.flag-bits').forEach((bits) => {
    bits.textContent = '1'.repeat(game.level).padEnd(TOTAL_LEVELS, '0');
    bits.setAttribute('aria-label', `${game.level} of ${TOTAL_LEVELS} flags found`);
  });
};

const execute = async (command) => {
  print(`> ${command}`, 'echo');
  const { lines, action } = await game.run(command);
  if (action === 'clear') output.replaceChildren();
  if (action === 'close') dialog.close();
  lines.forEach((line) => print(line));
  showFlags();
  output.scrollTop = output.scrollHeight;
};

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const command = input.value;
  input.value = '';
  execute(command);
});

document.querySelector('.chips').addEventListener('click', (event) => {
  const command = event.target.dataset?.cmd;
  if (command) execute(command);
});

document.querySelector('.console-close').addEventListener('click', () => dialog.close());

document.querySelectorAll('.ctf-open').forEach((button) => {
  button.addEventListener('click', () => {
    if (!output.hasChildNodes()) game.intro().forEach((line) => print(line));
    dialog.showModal();
  });
});

document.querySelector('.theme-toggle').addEventListener('click', () => {
  const root = document.documentElement;
  const current = root.dataset.theme ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  const next = current === 'dark' ? 'light' : 'dark';
  root.dataset.theme = next;
  try {
    localStorage.setItem('theme', next);
  } catch {
    // Storage can be blocked. The choice still applies for this visit.
  }
});

const navLinks = new Map([...document.querySelectorAll('.bar nav a')].map((link) => [link.hash.slice(1), link]));
const spy = new IntersectionObserver((entries) => {
  entries.forEach(({ isIntersecting, target }) => {
    if (isIntersecting) navLinks.forEach((link, id) => link.toggleAttribute('aria-current', id === target.id));
  });
}, { rootMargin: '-40% 0px -55% 0px' });
document.querySelectorAll('.block').forEach((section) => spy.observe(section));

window.addEventListener('load', () => {
  const entries = [...performance.getEntriesByType('navigation'), ...performance.getEntriesByType('resource')];
  const bytes = entries.reduce((total, entry) => total + entry.encodedBodySize, 0);
  if (bytes) document.querySelector('#page-weight').textContent = `This page weighs ${Math.ceil(bytes / 1024)} KB across ${entries.length} files.`;
});

initLab(fetchHeaders);

// These controls need JavaScript, so they appear only when it is available.
document.querySelectorAll('[data-needs-js]').forEach((element) => { element.hidden = false; });
