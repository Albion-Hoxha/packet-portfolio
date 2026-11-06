import { dissect, gradeHeaders, subnet, traceEdge } from './lab.js';

const SAMPLE_HEADER = '45 00 00 54 1a 2b 40 00 40 01 34 32 c0 00 02 0e c6 33 64 0a';

const element = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

function initSubnet() {
  const address = document.querySelector('#subnet-ip');
  const prefix = document.querySelector('#subnet-prefix');
  const prefixValue = document.querySelector('#subnet-prefix-value');
  const error = document.querySelector('#subnet-error');
  const grid = document.querySelector('.bitgrid');
  const readout = document.querySelector('.readout');
  const cells = Array.from({ length: 32 }, () => grid.appendChild(element('span')));

  const update = () => {
    const bits = Number(prefix.value);
    const result = subnet(address.value, bits);
    prefixValue.textContent = `/${bits}`;
    error.textContent = result.error ?? '';
    address.setAttribute('aria-invalid', String(Boolean(result.error)));
    readout.classList.toggle('stale', Boolean(result.error));
    if (result.error) return;
    cells.forEach((cell, i) => {
      cell.textContent = result.bits[i];
      cell.classList.toggle('net', i < bits);
    });
    readout.querySelectorAll('dd').forEach((value) => {
      const field = result[value.dataset.key];
      value.textContent = typeof field === 'number' ? field.toLocaleString('en-US') : field;
    });
  };

  address.form.addEventListener('submit', (event) => event.preventDefault());
  address.addEventListener('input', update);
  prefix.addEventListener('input', update);
  update();
}

function initDissector() {
  const input = document.querySelector('#dissect-input');
  const error = document.querySelector('#dissect-error');
  const output = document.querySelector('#dissect-output');

  const update = () => {
    output.replaceChildren();
    const result = dissect(input.value);
    const empty = !input.value.trim();
    error.textContent = empty ? '' : result.error ?? '';
    input.setAttribute('aria-invalid', String(!empty && Boolean(result.error)));
    if (result.error) return;
    result.fields.forEach(({ name, width, value, bad }) => {
      const cell = element('div', `bit-field span-${width}${bad ? ' bad' : ''}`);
      cell.append(element('span', 'tag', name), element('span', 'value', value));
      output.append(cell);
    });
  };

  input.form.addEventListener('submit', (event) => event.preventDefault());
  input.addEventListener('input', update);
  document.querySelector('#dissect-sample').addEventListener('click', () => {
    input.value = SAMPLE_HEADER;
    update();
  });
}

function initHeaderReport(fetchHeaders) {
  const run = document.querySelector('#headers-run');
  const score = document.querySelector('#headers-score');
  const report = document.querySelector('#headers-report');

  run.addEventListener('click', async () => {
    run.disabled = true;
    report.replaceChildren();
    score.textContent = 'Checking...';
    try {
      const { headers } = await fetchHeaders();
      const results = gradeHeaders(headers);
      score.textContent = `${results.filter((r) => r.passed).length} of ${results.length} checks passed`;
      results.forEach(({ name, why, passed }) => {
        const row = element('li', passed ? 'pass' : 'fail');
        row.append(element('span', 'mark', passed ? 'PASS' : 'FAIL'), element('strong', '', name), element('span', 'why', why));
        report.append(row);
      });
    } catch {
      score.textContent = 'Could not reach the site. Try again.';
    }
    run.disabled = false;
  });
}

function initRouteTrace(fetchHeaders) {
  const run = document.querySelector('#trace-run');
  const status = document.querySelector('#trace-status');
  const hops = document.querySelector('#trace-hops');

  const hop = (label, value) => {
    const row = element('li');
    row.append(element('span', 'tag', label), element('span', 'value', value));
    hops.append(row);
  };

  run.addEventListener('click', async () => {
    run.disabled = true;
    hops.replaceChildren();
    status.textContent = 'Tracing...';
    try {
      const start = performance.now();
      const { headers } = await fetchHeaders();
      const milliseconds = Math.round(performance.now() - start);
      const trace = traceEdge(headers);
      status.textContent = trace.onAws
        ? `Round trip: ${milliseconds} ms`
        : `Round trip: ${milliseconds} ms. This copy is not behind AWS, so there is no edge to show.`;
      if (trace.onAws) {
        hop('YOU', 'Your browser');
        hop('AWS EDGE', `${trace.city} (${trace.pop})`);
        hop('CACHE', trace.cacheHit ? 'Hit: served from the edge' : 'Miss: fetched from the origin');
        hop('ORIGIN', trace.origin);
      }
    } catch {
      status.textContent = 'Could not reach the site. Try again.';
    }
    run.disabled = false;
  });
}

export function initLab(fetchHeaders) {
  initSubnet();
  initDissector();
  initHeaderReport(fetchHeaders);
  initRouteTrace(fetchHeaders);
}
