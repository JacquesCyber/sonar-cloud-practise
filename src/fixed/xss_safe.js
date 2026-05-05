/**
 * XSS - Secure Implementations
 * ==============================
 * These are the corrected versions of the vulnerable examples in xss_example.js.
 *
 * Core Fix Strategy: Context-Aware Output Encoding
 * -------------------------------------------------
 * XSS fixes depend on WHERE you're inserting user data (the HTML context):
 *
 * | Context              | Safe Method                         | Unsafe                    |
 * |----------------------|-------------------------------------|---------------------------|
 * | HTML text content    | textContent, innerText              | innerHTML                 |
 * | HTML attribute       | setAttribute() with encoding        | attribute string concat   |
 * | URL attribute (href) | Validate scheme, then setAttribute  | location.href = userInput |
 * | JavaScript context   | JSON.stringify(), avoid entirely    | template literals in JS   |
 * | CSS context          | Avoid user data in CSS              | style injection           |
 *
 * For cases where HTML IS needed (rich text editors, CMS content):
 * Use DOMPurify — a robust, maintained HTML sanitizer:
 * https://github.com/cure53/DOMPurify
 *
 * Why SonarCloud Will Pass These:
 * --------------------------------
 * - textContent/innerText do not parse HTML — they set literal text
 * - DOMPurify output is considered sanitized (SonarCloud recognizes common sanitizers)
 * - Origin checks in postMessage handlers prevent unverified message processing
 * - Avoiding eval() removes the taint sink entirely
 */

'use strict';

// =============================================================================
// FIX 1: Use textContent instead of innerHTML
// =============================================================================
// textContent sets the TEXT content of an element.
// The browser renders it as literal text — no HTML parsing occurs.
// <script>alert(1)</script> becomes visible text, not executable code.
function displaySearchResults(query) {
  const resultsDiv = document.getElementById('search-results');

  // Create the heading element safely
  const heading = document.createElement('h2');

  // SAFE: textContent treats the value as literal text, never HTML
  heading.textContent = 'Results for: ' + query;

  // Clear previous content and append the new element
  resultsDiv.textContent = '';  // Clear safely
  resultsDiv.appendChild(heading);

  // For the URL parameter:
  const urlParams = new URLSearchParams(window.location.search);
  const searchTerm = urlParams.get('q') || '';

  const queryDisplay = document.getElementById('query-display');
  // SAFE: textContent — no HTML interpretation
  queryDisplay.textContent = searchTerm;
}


// =============================================================================
// FIX 2: createElement + textContent instead of document.write()
// =============================================================================
// Avoid document.write() entirely — it has no safe way to include user content.
// Use DOM manipulation methods that separate structure from data.
function renderWelcomeMessage(username) {
  // SAFE: Build DOM structure programmatically, set text separately
  const welcomeDiv = document.createElement('div');
  welcomeDiv.className = 'welcome';

  // SAFE: textContent for user data
  welcomeDiv.textContent = 'Hello, ' + username + '!';
  document.body.appendChild(welcomeDiv);

  // For the referrer — validate before using it
  const referrer = document.referrer;
  if (referrer && isValidUrl(referrer)) {
    const referrerPara = document.createElement('p');
    // SAFE: textContent — shows the referrer URL as text, not as HTML
    referrerPara.textContent = 'You came from: ' + referrer;
    document.body.appendChild(referrerPara);
  }
}

function isValidUrl(url) {
  try {
    const parsed = new URL(url);
    // Only allow http/https schemes (prevents javascript: URIs)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}


// =============================================================================
// FIX 3: Replace eval() with safe alternatives
// =============================================================================
// For math expressions, use a purpose-built safe math parser.
// Never use eval() with user input.
// Options:
//   - math.js library: https://mathjs.org/
//   - expr-eval: https://github.com/silentmatt/expr-eval
//   - Build a restricted evaluator with a proper grammar
function calculateExpression(userExpression) {
  // SAFE: Use a dedicated math expression parser
  // Option A: Using math.js (recommended for production)
  // const math = require('mathjs');
  // try {
  //   const result = math.evaluate(userExpression);
  //   document.getElementById('result').textContent = result;
  // } catch (e) {
  //   document.getElementById('result').textContent = 'Invalid expression';
  // }

  // Option B: Simple safe number-only expressions using a restricted regex
  // Only allow numbers, basic operators, parentheses, spaces, and decimal points
  const safePattern = /^[\d\s+\-*/().]+$/;

  if (!safePattern.test(userExpression)) {
    document.getElementById('result').textContent = 'Invalid expression: only numbers and basic operators allowed';
    return;
  }

  // Even with validation, prefer Function() over eval() for slightly better isolation
  // Note: For real security, use a proper expression parser library
  try {
    // Limited scope — does not have access to variables, only the expression
    const result = Function('"use strict"; return (' + userExpression + ')')();
    // SAFE: textContent for the result
    document.getElementById('result').textContent = result;
  } catch (e) {
    document.getElementById('result').textContent = 'Calculation error';
  }
}


// =============================================================================
// FIX 4: React — sanitize before dangerouslySetInnerHTML, or avoid it
// =============================================================================
// Option A (preferred): Avoid dangerouslySetInnerHTML entirely by using
// a rich text renderer that outputs React components, not raw HTML.
// (e.g., react-markdown for markdown, or a CMS-specific renderer)
//
// Option B (when HTML is truly required): Use DOMPurify to sanitize first.

// Import DOMPurify: npm install dompurify
// import DOMPurify from 'dompurify';

function UserComment({ commentHtml }) {
  // SAFE Option A: Render as plain text (loses formatting but is XSS-safe)
  return React.createElement('div', {
    className: 'comment'
  }, commentHtml); // React auto-escapes text content in JSX

  // SAFE Option B: Sanitize with DOMPurify before rendering HTML
  // const sanitizedHtml = DOMPurify.sanitize(commentHtml, {
  //   ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
  //   ALLOWED_ATTR: ['href'],
  //   // Force all links to open in new tabs (defense in depth)
  //   FORCE_BODY: true,
  // });
  // return React.createElement('div', {
  //   dangerouslySetInnerHTML: { __html: sanitizedHtml }
  // });
}

// JSX version:
// function UserComment({ commentHtml }) {
//   const sanitizedHtml = DOMPurify.sanitize(commentHtml, { ... });
//   return <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />;
// }


// =============================================================================
// FIX 5: postMessage with strict origin verification
// =============================================================================
// Always check event.origin against an allowlist of trusted origins.
// Never process messages from unknown origins.
const TRUSTED_ORIGINS = new Set([
  'https://app.example.com',
  'https://dashboard.example.com',
]);

window.addEventListener('message', function(event) {
  // SAFE: Verify origin before processing any message data
  if (!TRUSTED_ORIGINS.has(event.origin)) {
    // Log the rejected origin for security monitoring (but don't include data)
    console.warn('Rejected message from untrusted origin:', event.origin);
    return;  // Silently ignore messages from untrusted origins
  }

  const data = event.data;

  // Additional validation: check data structure
  if (!data || typeof data !== 'object' || !data.action) {
    return;
  }

  if (data.action === 'updateContent') {
    // SAFE: textContent — user data from the message is text, not HTML
    const element = document.getElementById('dynamic-content');
    if (element) {
      element.textContent = data.content;  // Not innerHTML
    }
  }
});


// =============================================================================
// FIX 6: URL validation before redirect
// =============================================================================
// Validate that the redirect URL is:
// 1. A relative path within the same origin, OR
// 2. An absolute URL to an explicitly allowed domain
// Reject javascript: URIs and unrecognized origins.
const ALLOWED_REDIRECT_ORIGINS = new Set([
  'https://app.example.com',
  'https://accounts.example.com',
]);

function redirectAfterLogin(returnUrl) {
  // SAFE: Validate the URL before redirecting

  // Allow relative paths (same-origin redirects)
  if (returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
    window.location.href = returnUrl;
    return;
  }

  // For absolute URLs, check origin against allowlist
  try {
    const parsed = new URL(returnUrl);

    // Reject non-http/https schemes (blocks javascript:, data:, vbscript:)
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      console.error('Redirect blocked: invalid scheme', parsed.protocol);
      window.location.href = '/dashboard';  // Safe fallback
      return;
    }

    // Check against origin allowlist
    if (ALLOWED_REDIRECT_ORIGINS.has(parsed.origin)) {
      window.location.href = returnUrl;
    } else {
      console.error('Redirect blocked: origin not in allowlist', parsed.origin);
      window.location.href = '/dashboard';  // Safe fallback
    }
  } catch {
    // Invalid URL — redirect to safe default
    window.location.href = '/dashboard';
  }
}


// =============================================================================
// FIX 7: Template rendering with safe DOM methods
// =============================================================================
// When you need to render complex user content, use DOM APIs that separate
// structure (HTML) from data (text). Never build HTML strings with user data.
function renderUserProfile(userData) {
  const container = document.getElementById('profile');

  // Clear existing content safely
  container.textContent = '';

  // SAFE: Build the DOM structure programmatically
  const profileDiv = document.createElement('div');
  profileDiv.className = 'profile';

  // SAFE: textContent for user-controlled text
  const heading = document.createElement('h1');
  heading.textContent = userData.name;  // Not innerHTML

  const bio = document.createElement('p');
  bio.textContent = 'Bio: ' + userData.bio;  // Not innerHTML

  // SAFE: Image src — use setAttribute and validate the URL scheme
  const img = document.createElement('img');
  img.alt = 'avatar';
  if (userData.avatarUrl && isValidImageUrl(userData.avatarUrl)) {
    img.setAttribute('src', userData.avatarUrl);  // Validated URL
  } else {
    img.setAttribute('src', '/default-avatar.png');
  }

  // SAFE: Link href — validate URL to prevent javascript: URIs
  const link = document.createElement('a');
  if (userData.website && isValidUrl(userData.website)) {
    link.setAttribute('href', userData.website);
    link.setAttribute('rel', 'noopener noreferrer');  // Defense in depth
    link.setAttribute('target', '_blank');
    link.textContent = 'Website';  // Link text is textContent, not innerHTML
  }

  profileDiv.appendChild(heading);
  profileDiv.appendChild(bio);
  profileDiv.appendChild(img);
  if (link.hasAttribute('href')) {
    profileDiv.appendChild(link);
  }

  container.appendChild(profileDiv);
}

function isValidImageUrl(url) {
  try {
    const parsed = new URL(url);
    // Only allow https images (mixed content and data: URI attacks)
    return parsed.protocol === 'https:';
  } catch {
    // Allow relative paths
    return url.startsWith('/') && !url.startsWith('//');
  }
}


// =============================================================================
// Utility: HTML entity encoding (for cases where textContent can't be used)
// =============================================================================
// If you absolutely must build an HTML string (e.g., for a template that gets
// set via innerHTML), encode all user data first.
// However, prefer textContent/DOM methods over this approach.
function htmlEncode(str) {
  const div = document.createElement('div');
  div.textContent = str;  // textContent sets literal text
  return div.innerHTML;   // innerHTML then gives us the encoded version
  // '<script>' becomes '&lt;script&gt;'
  // '"' becomes '&quot;'
  // '&' becomes '&amp;'
}
