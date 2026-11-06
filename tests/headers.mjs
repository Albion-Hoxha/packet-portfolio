import { readFileSync } from 'node:fs';

// shortcut: reads only the flat key/value layout of customHttp.yml, not general YAML.
export const readHeaders = () => {
  const yaml = readFileSync(new URL('../customHttp.yml', import.meta.url), 'utf8');
  const pairs = yaml.matchAll(/- key: '([^']+)'\s+value: (?:"([^"]*)"|'([^']*)')/g);
  return Object.fromEntries([...pairs].map(([, key, double, single]) => [key, double ?? single]));
};
