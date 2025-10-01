// Proxy configuration for Anti-Phishing Gateway
const PROXY_HOST = 'localhost';
const PROXY_PORT = 8081;

// Set proxy when extension starts
chrome.runtime.onStartup.addListener(() => {
  setProxy();
});

// Set proxy when extension is installed/enabled
chrome.runtime.onInstalled.addListener(() => {
  setProxy();
});

// Function to configure proxy
function setProxy() {
  const config = {
    mode: 'fixed_servers',
    rules: {
      singleProxy: {
        scheme: 'http',
        host: PROXY_HOST,
        port: PROXY_PORT
      },
      bypassList: []
    }
  };

  chrome.proxy.settings.set({
    value: config,
    scope: 'regular'
  }, () => {
    console.log('Proxy configured for Anti-Phishing Gateway');
  });
}