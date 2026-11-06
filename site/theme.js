// Runs before first paint so a saved theme never flashes the wrong colours.
try {
  const saved = localStorage.getItem('theme');
  if (saved === 'light' || saved === 'dark') document.documentElement.dataset.theme = saved;
} catch {
  // Storage can be blocked. The system theme still applies.
}
