// content.js — DOM analysis for brand impersonation and unsafe credential fields.

const BRAND_PATTERNS = [
  { brand: 'PayPal',          domains: ['paypal.com'] },
  { brand: 'Google',          domains: ['google.com'] },
  { brand: 'Microsoft',       domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com'] },
  { brand: 'Apple',           domains: ['apple.com', 'icloud.com'] },
  { brand: 'Amazon',          domains: ['amazon.com'] },
  { brand: 'Facebook',        domains: ['facebook.com', 'fb.com'] },
  { brand: 'Netflix',         domains: ['netflix.com'] },
  { brand: 'Chase',           domains: ['chase.com'] },
  { brand: 'Wells Fargo',     domains: ['wellsfargo.com'] },
  { brand: 'Bank of America', domains: ['bankofamerica.com'] },
  { brand: 'Steam',           domains: ['steampowered.com', 'steamcommunity.com'] },
  { brand: 'Discord',         domains: ['discord.com'] },
  { brand: 'Instagram',       domains: ['instagram.com'] },
  { brand: 'Twitter',         domains: ['twitter.com', 'x.com'] },
];

function getCoreDomain(hostname) {
  const parts = hostname.split('.');
  return parts.length <= 2 ? hostname : parts.slice(-2).join('.');
}

function analyzePageContent() {
  const signals = [];
  const hostname = location.hostname.toLowerCase();
  const coreDomain = getCoreDomain(hostname);
  const isHttps = location.protocol === 'https:';
  const hasPasswordField = document.querySelectorAll('input[type="password"]').length > 0;

  // only run deeper checks when there's a credential field — avoids false positives on news/blogs
  if (hasPasswordField) {
    if (!isHttps) {
      signals.push({ type: 'password_on_http', severity: 'high', label: 'Password field on non-HTTPS page' });
    }

    // brand impersonation: check title + headings only (fast, low false-positive rate)
    const headingText = Array.from(document.querySelectorAll('h1, h2'))
      .map((el) => el.textContent).join(' ').slice(0, 600);
    const pageText = `${document.title} ${headingText}`.toLowerCase();

    for (const { brand, domains } of BRAND_PATTERNS) {
      if (pageText.includes(brand.toLowerCase())) {
        const isOfficial = domains.some((d) => coreDomain === d || hostname.endsWith(`.${d}`));
        if (!isOfficial) {
          signals.push({ type: 'brand_impersonation', severity: 'high', label: `Impersonating ${brand}` });
        }
      }
    }
  }

  return signals;
}

const signals = analyzePageContent();
chrome.runtime.sendMessage({ type: 'CONTENT_SIGNALS', signals, url: location.href });
