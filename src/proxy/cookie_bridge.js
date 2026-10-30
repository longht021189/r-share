// Injected by the proxy first in every HTML page it serves.
//
// The webview keeps no cookies for a custom scheme, so cookies that page
// scripts write through `document.cookie` (e.g. a bot check's answer, right
// before it reloads the page) would never reach the server. Hand each write to
// the proxy, which stores it in the cookie jar it sends requests with.
//
// `__ENDPOINT__` is replaced by the proxy with the URL of its cookie API.
(() => {
  const endpoint = '__ENDPOINT__';
  const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  if (!descriptor?.get || !descriptor.set) return;
  const { get, set } = descriptor;
  // The page may replace `fetch` later; keep the native one.
  const send = window.fetch.bind(window);
  Object.defineProperty(document, 'cookie', {
    configurable: true,
    get() {
      return get.call(this);
    },
    set(value) {
      set.call(this, value);
      try {
        const query = `u=${encodeURIComponent(location.hostname)}&c=${encodeURIComponent(value)}`;
        send(`${endpoint}?${query}`, { mode: 'no-cors', keepalive: true }).catch(() => {});
      } catch {
        // Best effort: the cookie is still set in the page itself.
      }
    },
  });
})();
