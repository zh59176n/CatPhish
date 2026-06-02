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

const CATEGORY_MAP = [
  { label: 'AI & Productivity', hosts: ['chatgpt', 'openai', 'claude', 'gemini', 'notion', 'figma', 'microsoft 365', 'slack'] },
  { label: 'Social Media', hosts: ['facebook', 'instagram', 'twitter', 'x.com', 'tiktok', 'linkedin', 'snapchat', 'reddit', 'pinterest', 'tumblr'] },
  { label: 'Shopping', hosts: ['amazon', 'ebay', 'etsy', 'walmart', 'target', 'aliexpress', 'shopify', 'bestbuy', 'nike'] },
  { label: 'Banking & Finance', hosts: ['chase', 'wellsfargo', 'paypal', 'venmo', 'capitalone', 'hsbc', 'citibank', 'barclays', 'bankofamerica'] },
  { label: 'Education', hosts: ['edu', 'coursera', 'udemy', 'khanacademy', 'edx', 'mit', 'stanford', 'nyu', 'cuny'] },
  { label: 'News & Media', hosts: ['cnn', 'bbc', 'nytimes', 'washingtonpost', 'foxnews', 'reuters', 'bloomberg', 'vice'] },
  { label: 'Technology', hosts: ['google', 'apple', 'microsoft', 'intel', 'nvidia', 'adobe', 'oracle', 'tesla'] },
  { label: 'Entertainment', hosts: ['netflix', 'spotify', 'youtube', 'twitch', 'disney', 'hulu', 'peacock', 'soundcloud'] },
  { label: 'Government', hosts: ['gov', 'state', 'irs', 'usa', 'nhs', 'gov.uk', 'canada.ca'] }
];

const LOGIN_KEYWORDS = ['login', 'signin', 'secure', 'account', 'auth', 'verify', 'authorize', 'checkout', 'portal'];

function isLoginPage(path) {
  return LOGIN_KEYWORDS.some((word) => path.includes(`/${word}`) || path.includes(`${word}?`) || path.includes(`${word}#`) || path.endsWith(word));
}

function getWebsiteCategory(url) {
  if (!url) return 'Unknown';
  const hostname = url.hostname.toLowerCase();
  const path = `${url.pathname}${url.search}${url.hash}`.toLowerCase();

  for (const entry of CATEGORY_MAP) {
    if (entry.hosts.some((term) => hostname.includes(term) || path.includes(term))) {
      return entry.label;
    }
  }

  return 'Unknown';
}

function getDomainReputation(domain) {
  if (!domain) {
    return { status: 'unknown', score: null, source: 'none', confidence: 0 };
  }

  const trusted = KNOWN_SAFE_DOMAINS.some((safeDomain) => domain === safeDomain || domain.endsWith(`.${safeDomain}`));

  return {
    status: trusted ? 'trusted' : 'unknown',
    score: trusted ? 80 : null,
    source: trusted ? 'placeholder' : 'none',
    confidence: trusted ? 0.5 : 0
  };
}

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
      category: 'Unknown',
      reputation: { status: 'unknown', score: null, source: 'placeholder' },
      score: 0,
      level: 'Low',
      reasons: ['No URL available'],
      summary: 'No page was detected.',
      tip: 'Open a website and click CatPhish to scan the page.',
      trustExplanation: 'No site is currently loaded yet.'
    };
  }

  let url;
  try {
    url = new URL(rawUrl);
  } catch (error) {
    return {
      url: rawUrl,
      domain,
      category: 'Unknown',
      reputation: { status: 'unknown', score: null, source: 'placeholder' },
      score: 60,
      level: 'High',
      reasons: ['Malformed URL'],
      summary: 'The page URL could not be parsed.',
      tip: 'Be careful with links that look broken or strange.',
      trustExplanation: 'The URL format could not be interpreted, so this result is an initial warning.'
    };
  }

  const hostname = url.hostname.toLowerCase();
  domain = getCoreDomain(hostname);
  const pathAndQuery = `${url.pathname}${url.search}${url.hash}`.toLowerCase();
  const safeDomain = isKnownSafeDomain(hostname);
  const category = getWebsiteCategory(url);
  const isLogin = isLoginPage(pathAndQuery);
  const reputation = getDomainReputation(domain);

  const positiveSignals = [];
  const concerns = [];
  const scoreNotes = [];

  if (url.protocol === 'https:') {
    positiveSignals.push('Secure HTTPS connection detected');
  } else {
    score += 25;
    concerns.push('Connection is not HTTPS.');
    scoreNotes.push('HTTPS is missing');
  }

  if (category !== 'Unknown') {
    positiveSignals.push(`Recognized ${category} website`);
  } else {
    concerns.push('Website category could not be identified.');
  }

  if (safeDomain) {
    positiveSignals.push('Domain appears legitimate');
  }

  const foundKeywords = SUSPICIOUS_WORDS.filter((word) => pathAndQuery.includes(word));
  const loginKeywords = foundKeywords.filter((word) => LOGIN_KEYWORDS.includes(word));

  if (foundKeywords.length) {
    foundKeywords.forEach((word) => {
      const isLoginSignal = LOGIN_KEYWORDS.includes(word);
      const signalText = `URL contains the keyword: ${word}`;

      if (safeDomain && isLogin && isLoginSignal) {
        positiveSignals.push('Recognized a login page on a trusted domain');
        return;
      }

      if (isLogin && isLoginSignal) {
        score += safeDomain ? 3 : 8;
        concerns.push('Login-related page detected. Verify the domain before entering credentials.');
        scoreNotes.push('Login page detected');
        return;
      }

      score += safeDomain ? 5 : 10;
      concerns.push(`Suspicious URL keyword detected: ${word}`);
      scoreNotes.push(signalText);
    });
  } else {
    positiveSignals.push('No suspicious URL patterns found');
  }

  if (isLogin && safeDomain) {
    positiveSignals.push('Login pages are common and not inherently suspicious');
  }

  if (isIpAddress(hostname)) {
    score += 25;
    concerns.push('IP address used instead of a standard domain.');
    scoreNotes.push('IP address host detected');
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 15;
    concerns.push('Domain contains many hyphens.');
    scoreNotes.push('Many hyphens in hostname');
  }

  const digitCount = (hostname.match(/\d/g) || []).length;
  if (digitCount >= 4) {
    score += 15;
    concerns.push('Domain contains many numbers.');
    scoreNotes.push('Many digits in hostname');
  }

  const hostParts = hostname.split('.').filter(Boolean);
  if (hostParts.length >= 4 && !isIpAddress(hostname)) {
    score += 10;
    concerns.push('Many subdomains were detected.');
    scoreNotes.push('Complex subdomain structure');
  }

  if (rawUrl.length > 100) {
    score += 10;
    concerns.push('URL is longer than 100 characters.');
    scoreNotes.push('Long URL detected');
  } else {
    positiveSignals.push('URL length appears normal');
  }

  if (!isIpAddress(hostname) && foundKeywords.length === 0 && category !== 'Unknown') {
    positiveSignals.push('No impersonation indicators detected');
  }

  score = Math.min(100, score);
  let level = 'Low';
  if (score >= 60) {
    level = 'High';
  } else if (score >= 30) {
    level = 'Medium';
  }

  const summary =
    level === 'High'
      ? 'This page shows multiple strong risk signals.'
      : level === 'Medium'
      ? 'Some risk signals were found. Proceed carefully.'
      : 'This page looks normal, but keep checking before sharing sensitive details.';

  const tip =
    level === 'High'
      ? 'Avoid entering passwords or personal info until you verify the site.'
      : level === 'Medium'
      ? isLogin
        ? 'Even trusted login pages should be checked carefully before entering credentials.'
        : 'Check the page URL and avoid unfamiliar login forms.'
      : category === 'Shopping'
      ? 'Verify checkout pages and payment details before making purchases.'
      : category === 'Unknown'
      ? 'Consider researching this domain before sharing personal information.'
      : 'Everything looks normal. Continue to verify websites before sharing sensitive information.';

  let trustExplanation;
  if (safeDomain) {
    trustExplanation = `CatPhish recognized this website as a trusted ${category} platform.`;
    if (isLogin) {
      trustExplanation += ' Login pages are common here and not inherently suspicious.';
    } else {
      trustExplanation += ' HTTPS is enabled and no suspicious URL patterns were detected.';
    }
  } else if (category !== 'Unknown') {
    trustExplanation = `CatPhish recognized this website as ${category}.`;
    if (isLogin) {
      trustExplanation += ' Login pages are common for this category, so verify the domain carefully.';
    } else {
      trustExplanation += ' Review the URL and avoid sharing credentials unless you trust the domain.';
    }
  } else {
    trustExplanation = 'CatPhish could not identify this website category. Review the domain carefully before entering personal information.';
  }

  if (positiveSignals.length === 0) {
    positiveSignals.push('CatPhish did not detect any common positive signals yet.');
  }

  if (concerns.length === 0) {
    concerns.push('CatPhish didn’t spot any common phishing indicators on this page.');
  }

  const scoreReason = scoreNotes.length
    ? `Score note: ${scoreNotes.join('; ')}.`
    : 'Score note: normal URL structure and site signals.';

  return {
    url: rawUrl,
    domain,
    category,
    reputation,
    reputationStatus: reputation.status,
    reputationSource: reputation.source,
    reputationConfidence: reputation.confidence,
    score,
    level,
    positiveSignals,
    concerns,
    summary,
    tip,
    trustExplanation,
    scoreReason
  };
}
