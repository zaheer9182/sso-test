/**
 * MOJ CHATBOT - UNIFIED SSO MODULE
 *
 * Runs inside the chatbot application itself (the iframe content),
 * works correctly regardless of which page embeds it - SharePoint
 * 2019 (HTTP) or SharePoint Online (HTTPS) - without needing to know
 * in advance which one it's on.
 *
 * HOW IT DECIDES WHICH APPROACH TO USE:
 * It checks window.crypto.subtle directly - the actual condition that
 * determines which approach is needed - rather than guessing from the
 * page's URL or referrer. This means if SharePoint 2019 is later moved
 * to HTTPS, this code automatically starts using the standard, safer
 * approach there too, with no code change required.
 *
 *   crypto.subtle AVAILABLE   -> standard MSAL (ssoSilent/loginRedirect,
 *                                 real PKCE via the browser's own,
 *                                 secure implementation). This is what
 *                                 was tested and confirmed working on
 *                                 SharePoint Online.
 *
 *   crypto.subtle UNAVAILABLE -> custom PKCE flow, using a pure-JS
 *                                 SHA-256 implementation instead of
 *                                 crypto.subtle. This is what was
 *                                 tested and confirmed working on the
 *                                 current, HTTP SharePoint 2019 page.
 *
 * ============================================================
 * IMPORTANT, HONEST SECURITY NOTE ON THE crypto.subtle-UNAVAILABLE PATH:
 * ============================================================
 * This path was built and proven specifically because the client asked
 * whether it was possible, and to demonstrate the actual technical
 * limitation clearly. It works, but it does not restore what HTTPS
 * itself protects: the parent SharePoint 2019 page remains unencrypted
 * in transit, so its content (including this exchange) can still be
 * intercepted or altered by anyone positioned on the network. This is
 * a known, accepted trade-off for the current HTTP environment, not a
 * fully secure substitute for HTTPS. Confirm this is still the
 * intended, accepted approach before relying on it in production.
 * ============================================================
 *
 * Requires MSAL.js loaded first (for the crypto.subtle-available path):
 *   <script src="https://alcdn.msauth.net/browser/2.38.3/js/msal-browser.min.js"></script>
 *
 * USAGE:
 *   MojChatbotSso.init(function (result) {
 *     if (result.success) {
 *       console.log('Signed in as', result.upn, 'via', result.method);
 *       // send result.token and result.upn to your backend
 *     } else {
 *       console.error(result.errorCode, result.errorMessage);
 *     }
 *   });
 */

var MojChatbotSso = (function () {
  'use strict';

  // ===== CONFIGURATION =====
  // PRODUCTION - real client identity-mapping app (COMMENTED for this test run)
  var CLIENT_ID = '0dd93c83-b3c4-4070-bb0e-f4be7a8db3a9';
  var TENANT_ID = 'c3e95fdb-c64c-4f84-8388-f0c1c67f1f68';

  // LAB/TEST TENANT - ACTIVE for this test run
  //var CLIENT_ID = 'a5f76f5d-9883-49a6-9736-d96e908ca9bd';
  //var TENANT_ID = '44497ee7-e4f2-42ea-ac33-427a891f6b1a';

  var SCOPES_MSAL = ['openid', 'profile', 'User.Read'];
  var SCOPE_CUSTOM = 'User.Read';
  var RENEW_INTERVAL_MINUTES = 10;

  // Known hosts this app is expected to run on. Used only to validate
  // the dynamically-computed redirect URI below is on an expected
  // domain - NOT to override or replace it. Each entry's value is
  // this app's expected ROOT path on that host; if the app is ever
  // called from a different path (see getRedirectUri below), that's
  // flagged clearly in the console rather than silently guessed at.
  var KNOWN_HOSTS = {
    'dev.assistant.moj.gov.qa': 'https://dev.assistant.moj.gov.qa/',
    'stg.assistant.moj.gov.qa': 'https://stg.assistant.moj.gov.qa/',
    'assistant.moj.gov.qa': 'https://assistant.moj.gov.qa/',
    // TEST-ONLY entry, added for this validation run - NOT part of the real file
    'zaheer9182.github.io': 'https://zaheer9182.github.io/sso-test/live-test-wrapper.html',
  };

  // ============================================================
  // REDIRECT URI - dynamically computed from the actual page this
  // code is running on (window.location), NOT hardcoded. This is
  // the FRONT-END TEAM'S RESPONSIBILITY to get right: call
  // MojChatbotSso.init() from your app's root/entry point, before
  // any client-side routing changes the URL - otherwise the value
  // computed here will not match what's registered in Entra, and
  // sign-in will fail with a redirect URI mismatch error.
  //
  // This function ALWAYS logs the exact value it computes, and
  // ALWAYS logs an explicit warning if that value doesn't match the
  // expected root path for the current host - so this is never a
  // silent, hard-to-debug failure. Check the browser console first
  // if sign-in isn't working: it will show exactly what redirectUri
  // value was used and whether it looked as expected.
  //
  // Every exact value this can legitimately produce (one per real
  // environment/page this app is loaded from) must be registered
  // under the "Single-page application" platform on the app
  // registration in Azure - NOT "Web".
  // ============================================================
  function getRedirectUri() {
    var host = window.location.hostname;
    var dynamicUri = window.location.origin + window.location.pathname;

    log('Computed redirectUri:', dynamicUri, '(host:', host + ')');

    var expectedRoot = KNOWN_HOSTS[host];
    if (!expectedRoot) {
      logError(
        'UNRECOGNIZED HOST: "' + host + '" is not in KNOWN_HOSTS. ' +
        'Add this environment to KNOWN_HOSTS in this file AND register its exact ' +
        'URL under the SPA platform in Azure before sign-in can work here.'
      );
      return null;
    }

    if (dynamicUri !== expectedRoot) {
      logWarn(
        'Computed redirectUri (' + dynamicUri + ') differs from this host\'s expected root (' + expectedRoot + '). ' +
        'This usually means init() was called from a path other than the app\'s root - often caused by ' +
        'client-side routing having already changed the URL before init() ran. If sign-in fails with a ' +
        '"redirect URI mismatch" error, either call init() earlier (before routing changes the URL), or ' +
        'register this exact path (' + dynamicUri + ') under the SPA platform in Azure as well.'
      );
    }

    return dynamicUri;
  }
  // ============================================================

  var LOG_PREFIX = '[MojChatbotSso]';
  function log() { var a = Array.prototype.slice.call(arguments); a.unshift(LOG_PREFIX); console.log.apply(console, a); }
  function logWarn() { var a = Array.prototype.slice.call(arguments); a.unshift(LOG_PREFIX); console.warn.apply(console, a); }
  function logError() { var a = Array.prototype.slice.call(arguments); a.unshift(LOG_PREFIX); console.error.apply(console, a); }

  // ============================================================
  // PATH A: standard MSAL - used when crypto.subtle IS available.
  // Same proven logic confirmed working end-to-end on SharePoint
  // Online: checks cache first (avoids reload if already signed in
  // this session), then ssoSilent, then falls back to loginRedirect
  // only as a last resort.
  // ============================================================

  async function runStandardMsal(callback) {
    log('crypto.subtle available - using standard MSAL.');
    // Log which credentials are actually active at runtime - important
    // given this file supports switching between production and
    // lab/test credentials via commenting/uncommenting lines above.
    // This confirms, from the console alone, exactly which one is live.
    log('Active CLIENT_ID:', CLIENT_ID, '| Active TENANT_ID:', TENANT_ID);

    if (typeof msal === 'undefined') {
      logError('MSAL library not found. Make sure the MSAL <script> tag loads before this module.');
      callback({ success: false, errorCode: 'msal_not_loaded', errorMessage: 'MSAL library not found on the page.' });
      return;
    }

    var redirectUri = getRedirectUri();
    if (!redirectUri) {
      callback({ success: false, errorCode: 'unrecognized_host', errorMessage: 'This host is not configured in KNOWN_HOSTS.' });
      return;
    }

    var msalInstance = new msal.PublicClientApplication({
      auth: {
        clientId: CLIENT_ID,
        authority: 'https://login.microsoftonline.com/' + TENANT_ID,
        redirectUri: redirectUri,
      },
      cache: { cacheLocation: 'sessionStorage' },
    });

    await msalInstance.initialize();
    log('MSAL initialized.');

    var redirectResponse;
    try {
      redirectResponse = await msalInstance.handleRedirectPromise({ navigateToLoginRequestUrl: true });
      log('handleRedirectPromise resolved:', redirectResponse ? 'got a response (returning from a real redirect)' : 'null (no pending redirect - normal page load)');
    } catch (e) {
      logError('handleRedirectPromise threw:', e.errorCode, e.errorMessage);
      callback({ success: false, errorCode: e.errorCode, errorMessage: e.errorMessage });
      return;
    }

    if (redirectResponse) {
      log('SUCCESS via redirect return. UPN:', redirectResponse.account.username);
      callback({ success: true, method: 'msal_redirect', token: redirectResponse.accessToken, upn: redirectResponse.account.username, account: redirectResponse.account });
      startMsalRenewalTimer(msalInstance, redirectResponse.account, callback);
      return;
    }

    var existingAccounts = msalInstance.getAllAccounts();
    log('Cached accounts found:', existingAccounts.length);
    if (existingAccounts.length > 0) {
      try {
        log('Trying acquireTokenSilent from cache...');
        var cachedResponse = await msalInstance.acquireTokenSilent({ scopes: SCOPES_MSAL, account: existingAccounts[0] });
        log('SUCCESS from cache. UPN:', cachedResponse.account.username);
        callback({ success: true, method: 'msal_cache', token: cachedResponse.accessToken, upn: cachedResponse.account.username, account: cachedResponse.account });
        startMsalRenewalTimer(msalInstance, cachedResponse.account, callback);
        return;
      } catch (cacheErr) {
        logWarn('Cached account found but silent acquisition failed, falling through:', cacheErr.errorCode);
      }
    }

    try {
      log('No usable cached account - attempting ssoSilent...');
      var silentResponse = await msalInstance.ssoSilent({ scopes: SCOPES_MSAL });
      log('SUCCESS via ssoSilent. UPN:', silentResponse.account.username);
      callback({ success: true, method: 'msal_silent', token: silentResponse.accessToken, upn: silentResponse.account.username, account: silentResponse.account });
      startMsalRenewalTimer(msalInstance, silentResponse.account, callback);
    } catch (silentError) {
      logWarn('ssoSilent failed:', silentError.errorCode, silentError.errorMessage);
      log('Falling back to loginRedirect (page will now navigate away)...');
      await msalInstance.loginRedirect({ scopes: SCOPES_MSAL });
      // execution stops here - page navigates away
    }
  }

  function startMsalRenewalTimer(msalInstance, account, callback) {
    log('Starting silent renewal timer - every', RENEW_INTERVAL_MINUTES, 'minutes.');
    setInterval(function () {
      log('Renewal timer fired - attempting acquireTokenSilent...');
      msalInstance.acquireTokenSilent({ scopes: SCOPES_MSAL, account: account })
        .then(function (result) {
          log('Silent renewal SUCCESS.');
          callback({ success: true, method: 'msal_renewal', token: result.accessToken, upn: result.account.username, account: result.account });
        })
        .catch(function (err) { logWarn('Silent renewal failed, will retry next interval:', err.errorCode); });
    }, RENEW_INTERVAL_MINUTES * 60 * 1000);
  }

  // ============================================================
  // PATH B: custom PKCE (pure-JS SHA-256) - used when crypto.subtle
  // is UNAVAILABLE. Same proven logic confirmed working end-to-end
  // on the current, HTTP SharePoint 2019 page. See the security
  // note in this file's header comment before relying on this path.
  // ============================================================

  function sha256(messageBytes) {
    var K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    var bitLen = messageBytes.length * 8;
    var padLen = messageBytes.length + 1;
    while (padLen % 64 !== 56) padLen++;
    var padded = new Uint8Array(padLen + 8);
    padded.set(messageBytes);
    padded[messageBytes.length] = 0x80;
    var view = new DataView(padded.buffer);
    view.setUint32(padded.length - 4, bitLen >>> 0, false);
    view.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000), false);
    var numBlocks = padded.length / 64;
    var W = new Uint32Array(64);
    for (var block = 0; block < numBlocks; block++) {
      var offset = block * 64;
      for (var t = 0; t < 16; t++) W[t] = view.getUint32(offset + t * 4, false);
      for (t = 16; t < 64; t++) {
        var s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        var s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    var result = new Uint8Array(32);
    var resultView = new DataView(result.buffer);
    for (var i = 0; i < 8; i++) resultView.setUint32(i * 4, H[i], false);
    return result;
  }

  function base64UrlEncode(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function runCustomPkce(callback) {
    logWarn('crypto.subtle UNAVAILABLE (this page is not HTTPS) - using custom PKCE fallback. See this file\'s header comment for the security trade-off this involves.');
    log('Active CLIENT_ID:', CLIENT_ID, '| Active TENANT_ID:', TENANT_ID);

    var REDIRECT_URI = getRedirectUri();
    if (!REDIRECT_URI) {
      callback({ success: false, errorCode: 'unrecognized_host', errorMessage: 'This host is not configured in KNOWN_HOSTS.' });
      return;
    }

    var urlParams = new URLSearchParams(window.location.search);
    var returnedCode = urlParams.get('code');
    var returnedState = urlParams.get('state');
    log('URL has authorization code:', !!returnedCode);

    if (returnedCode) {
      log('Got authorization code back, exchanging for a token...');
      var storedVerifier = sessionStorage.getItem('moj_custom_pkce_verifier');
      var storedState = sessionStorage.getItem('moj_custom_pkce_state');
      log('Stored verifier present:', !!storedVerifier, '| Stored state present:', !!storedState);

      if (!storedVerifier) {
        logError('No stored code_verifier found in sessionStorage - cannot complete exchange. This usually means sessionStorage was cleared between the redirect and the return, or this page loaded in a different browser tab/session than the one that started sign-in.');
        callback({ success: false, errorCode: 'missing_verifier', errorMessage: 'No stored code_verifier found in sessionStorage.' });
        return;
      }
      if (returnedState !== storedState) {
        logError('State parameter mismatch - expected:', storedState, 'received:', returnedState, '- possible CSRF, aborting.');
        callback({ success: false, errorCode: 'state_mismatch', errorMessage: 'State parameter mismatch - possible CSRF.' });
        return;
      }

      try {
        log('Sending token exchange request to Entra ID...');
        var tokenResponse = await fetch('https://login.microsoftonline.com/' + TENANT_ID + '/oauth2/v2.0/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: CLIENT_ID,
            grant_type: 'authorization_code',
            code: returnedCode,
            redirect_uri: REDIRECT_URI,
            code_verifier: storedVerifier,
            scope: SCOPE_CUSTOM,
          }),
        });
        log('Token endpoint responded with HTTP status:', tokenResponse.status);
        var tokenData = await tokenResponse.json();

        window.history.replaceState({}, document.title, window.location.pathname);
        sessionStorage.removeItem('moj_custom_pkce_verifier');
        sessionStorage.removeItem('moj_custom_pkce_state');

        if (!tokenResponse.ok) {
          logError('Token exchange FAILED:', tokenData.error, '-', tokenData.error_description);
          callback({ success: false, errorCode: tokenData.error, errorMessage: tokenData.error_description || 'Token exchange failed.' });
          return;
        }

        log('SUCCESS via custom PKCE.');
        // JWTs use base64url encoding (with '-' and '_'), which the
        // standard atob() does not handle correctly - convert to
        // standard base64 first to avoid an intermittent decode
        // failure on tokens that happen to contain those characters.
        var payloadB64Url = tokenData.access_token.split('.')[1];
        var payloadB64 = payloadB64Url.replace(/-/g, '+').replace(/_/g, '/');
        while (payloadB64.length % 4 !== 0) payloadB64 += '=';
        var claims = JSON.parse(atob(payloadB64));
        var upn = claims.upn || claims.unique_name || claims.preferred_username || '';
        log('Token decoded successfully. UPN:', upn);
        callback({ success: true, method: 'custom_pkce', token: tokenData.access_token, upn: upn });
      } catch (e) {
        logError('Token exchange request itself failed (network/CORS/parse error):', e.message);
        callback({ success: false, errorCode: 'exchange_failed', errorMessage: e.message });
      }
      return;
    }

    // Starting fresh - generate PKCE using getRandomValues (available even
    // on HTTP - confirmed via MDN, only crypto.subtle is gated) and our
    // pure-JS SHA-256 for the challenge.
    var verifierBytes = new Uint8Array(32);
    window.crypto.getRandomValues(verifierBytes);
    var codeVerifier = base64UrlEncode(verifierBytes);

    var challengeBytes = sha256(new TextEncoder().encode(codeVerifier));
    var codeChallenge = base64UrlEncode(challengeBytes);

    var state = base64UrlEncode(window.crypto.getRandomValues(new Uint8Array(16)));

    sessionStorage.setItem('moj_custom_pkce_verifier', codeVerifier);
    sessionStorage.setItem('moj_custom_pkce_state', state);

    log('Generated PKCE pair via pure-JS SHA-256, redirecting to sign in...');

    var authUrl = 'https://login.microsoftonline.com/' + TENANT_ID + '/oauth2/v2.0/authorize?' +
      new URLSearchParams({
        client_id: CLIENT_ID,
        response_type: 'code',
        redirect_uri: REDIRECT_URI,
        scope: SCOPE_CUSTOM + ' openid profile',
        response_mode: 'query',
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state: state,
        prompt: 'none',
      }).toString();

    window.location.href = authUrl;
  }

  // ============================================================
  // ENTRY POINT - decides which path to use
  // ============================================================

  var initPromise = null;

  function decideAndRun(callback) {
    var subtleAvailable = !!(window.crypto && window.crypto.subtle);
    log('window.crypto.subtle:', subtleAvailable ? 'AVAILABLE' : 'UNAVAILABLE', '- current URL:', window.location.href);

    if (subtleAvailable) {
      return runStandardMsal(callback);
    } else {
      return runCustomPkce(callback);
    }
  }

  return {
    init: function (callback) {
      if (!initPromise) {
        initPromise = decideAndRun(callback || function () {}).catch(function (err) {
          logError('Unexpected error:', err);
          if (callback) callback({ success: false, errorCode: 'unexpected_error', errorMessage: String(err) });
        });
      }
      return initPromise;
    },
  };
})();
