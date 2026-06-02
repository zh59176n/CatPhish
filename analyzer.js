// analyzer.js — phishing detection logic separated from UI behavior.

const KNOWN_SAFE_DOMAINS = [
  'tumblr.com',
  'google.com',
  'github.com',
  'apple.com',
  'microsoft.com',
  'amazon.com',
  'facebook.com',
  'instagram.com',
  'twitter.com'
];

const SUSPICIOUS_WORDS = ['login', 'verify', 'secure', 'account', 'update', 'password', 'signin', 'confirm', 'reset'];

function isIpAddress(hostname) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
}

function isKnownSafeDomain(hostname) {
  return KNOWN_SAFE_DOMAINS.some((safeDomain) => hostname === safeDomain || hostname.endsWith(`.${safeDomain}`));
}

function getCoreDomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length <= 2) {
    return hostname;
  }
  return parts.slice(-2).join('.');
}

function analyzeUrl(rawUrl) {
  const reasons = [];
  let score = 0;
  let domain = 'unknown';

  if (!rawUrl) {
    return {
      url: '',
      domain,
      score: 0,
      level: 'Low',
      reasons: ['No URL available'],
      summary: 'No page was detected.',
      tip: 'Open a website and click CatPhish to scan the page.'
    };
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch (error) {
    return {
      url: rawUrl,
      domain,
      score: 60,
      level: 'High',
      reasons: ['Malformed URL'],
      summary: 'The page URL could not be parsed.',
      tip: 'Be careful with links that look broken or strange.'
    };
  }

  const hostname = url.hostname.toLowerCase();
  domain = getCoreDomain(hostname);
  const pathAndQuery = `${url.pathname}${url.search}${url.hash}`.toLowerCase();
  const safeDomain = isKnownSafeDomain(hostname);

  if (url.protocol !== 'https:') {
    score += 25;
    reasons.push('Connection is not HTTPS.');
  }

  const foundKeywords = SUSPICIOUS_WORDS.filter((word) => pathAndQuery.includes(word));
  foundKeywords.forEach((word) => {
    const points = safeDomain ? 5 : 10;
    score += points;
    reasons.push(`Suspicious keyword detected: ${word}`);
  });

  if (isIpAddress(hostname)) {
    score += 25;
    reasons.push('IP address used instead of a standard domain.');
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 15;
    reasons.push('Domain contains many hyphens.');
  }

  const digitCount = (hostname.match(/\d/g) || []).length;
  if (digitCount >= 4) {
    score += 15;
    reasons.push('Domain contains many numbers.');
  }

  const hostParts = hostname.split('.').filter(Boolean);
  if (hostParts.length >= 4 && !isIpAddress(hostname)) {
    score += 10;
    reasons.push('Many subdomains were detected.');
  }

  if (rawUrl.length > 100) {
    score += 10;
    reasons.push('URL is longer than 100 characters.');
  }

  score = Math.min(100, score);
  let level = 'Low';
  if (score >= 60) {
    level = 'High';
  } else if (score >= 30) {
    level = 'Medium';
  }

  if (reasons.length === 0) {
    reasons.push('No suspicious indicators were found.');
  }

  const summary =
    level === 'High'
      ? 'This page shows multiple strong risk signals.'
      : level === 'Medium'
      ? 'Some risk signals were found. Proceed carefully.'
      : 'The page looks mostly safe, but stay alert.';

  const tip =
    level === 'High'
      ? 'Avoid entering passwords or personal info until you verify the site.'
      : level === 'Medium'
      ? 'Check the page URL and avoid unfamiliar login forms.'
      : 'If the page looks legitimate, continue with caution.';

  return {
    url: rawUrl,
    domain,
    score,
    level,
    reasons,
    summary,
    tip
  };
}
