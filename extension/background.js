const API_URL = "http://127.0.0.1:8000/predict";
const PROCEED_OVERRIDE_TTL_MS = 60_000;

// Temporary allowlist while the model and dataset are still immature.
const TRUSTED_DOMAINS = [
  "google.com",
  "github.com",
  "microsoft.com",
  "apple.com",
];

function isTrustedDomain(targetUrl) {
  try {
    const { hostname } = new URL(targetUrl);
    return TRUSTED_DOMAINS.some((domain) =>
      hostname === domain || hostname.endsWith(`.${domain}`)
    );
  } catch (error) {
    console.warn("[Malicious URL Detector] Could not parse URL for allowlist check:", error);
    return false;
  }
}

const proceedOverrides = new Map();
const tabRiskState = new Map();

function getHostname(targetUrl) {
  try {
    return new URL(targetUrl).hostname;
  } catch (error) {
    return "";
  }
}

function buildBlockedPageUrl(targetUrl, confidence, riskLevel, reasons = []) {
  const blockedPage = new URL(chrome.runtime.getURL("blocked.html"));
  blockedPage.searchParams.set("url", targetUrl);
  blockedPage.searchParams.set("confidence", String(confidence));
  blockedPage.searchParams.set("risk", riskLevel);
  for (const reason of reasons.slice(0, 4)) {
    blockedPage.searchParams.append("reason", reason);
  }
  return blockedPage.toString();
}

function allowProceedOnce(tabId, targetUrl) {
  proceedOverrides.set(tabId, {
    url: targetUrl,
    hostname: getHostname(targetUrl),
    expiresAt: Date.now() + PROCEED_OVERRIDE_TTL_MS,
  });
}

function hasProceedOverride(tabId, targetUrl) {
  const override = proceedOverrides.get(tabId);
  if (!override) {
    return false;
  }

  const isExpired = Date.now() > override.expiresAt;
  const targetHostname = getHostname(targetUrl);
  const matchesTarget = override.url === targetUrl || (
    override.hostname &&
    targetHostname &&
    override.hostname === targetHostname
  );

  if (isExpired) {
    proceedOverrides.delete(tabId);
    return false;
  }

  return matchesTarget;
}

function rememberTabRisk(tabId, targetUrl, riskLevel, details = {}) {
  tabRiskState.set(tabId, { url: targetUrl, riskLevel, ...details });
}

function shouldSkipUrl(targetUrl) {
  return (
    targetUrl.startsWith("chrome://") ||
    targetUrl.startsWith("chrome-extension://") ||
    targetUrl.startsWith("about:") ||
    targetUrl.includes("127.0.0.1") ||
    targetUrl.includes("localhost")
  );
}

async function classifyUrl(targetUrl, domSignals = null) {
  const payload = { url: targetUrl };
  if (domSignals) {
    payload.dom_signals = domSignals;
  }

  const response = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`);
  }

  return response.json();
}

function showNotification(title, message) {
  chrome.notifications.create({
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/logo.png"),
    title,
    message,
    priority: 2
  }, () => {
    if (chrome.runtime.lastError) {
      console.error("Notification error:", chrome.runtime.lastError.message);
    }
  });
}

function showCautionBanner(tabId, targetUrl, result) {
  chrome.tabs.sendMessage(tabId, {
    type: "show-caution-banner",
    url: targetUrl,
    confidence: result.confidence,
    reasons: result.reasons || [],
  }, () => {
    if (chrome.runtime.lastError) {
      console.debug(
        "[Malicious URL Detector] Caution banner not shown:",
        chrome.runtime.lastError.message
      );
    }
  });
}

function handleRiskResult(tabId, targetUrl, result, source = "url-only") {
  const confidencePct = Math.round((result.confidence || 0) * 100);

  if (result.risk_level === "high") {
    console.warn(
      `[Malicious URL Detector] High-risk ${source} result for ${targetUrl} ` +
      `(Confidence: ${result.confidence})`
    );

    rememberTabRisk(tabId, targetUrl, "high", {
      confidence: result.confidence,
      reasons: result.reasons || [],
    });
    chrome.tabs.update(tabId, {
      url: buildBlockedPageUrl(targetUrl, result.confidence, result.risk_level, result.reasons),
    });

    showNotification(
      "Danger: Malicious Website Blocked!",
      `Blocked as high risk (${confidencePct}% confidence).`
    );
    return;
  }

  if (result.risk_level === "medium") {
    const previous = tabRiskState.get(tabId);
    if (previous?.url === targetUrl && previous.riskLevel === "medium") {
      return;
    }

    console.warn(
      `[Malicious URL Detector] Medium-risk ${source} result for ${targetUrl} ` +
      `(Confidence: ${result.confidence})`
    );
    rememberTabRisk(tabId, targetUrl, "medium", {
      confidence: result.confidence,
      reasons: result.reasons || [],
    });
    showCautionBanner(tabId, targetUrl, result);
    showNotification(
      "Caution: Suspicious Website",
      `This page looks suspicious (${confidencePct}% confidence). Review it carefully.`
    );
    return;
  }

  rememberTabRisk(tabId, targetUrl, "low", {
    confidence: result.confidence,
    reasons: result.reasons || [],
  });
  console.log(`[Malicious URL Detector] URL is safe: ${targetUrl}`);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "proceed-once") {
    const tabId = sender.tab?.id;
    const targetUrl = message.url;

    if (typeof tabId !== "number" || !targetUrl) {
      sendResponse({ ok: false });
      return false;
    }

    allowProceedOnce(tabId, targetUrl);
    chrome.tabs.update(tabId, { url: targetUrl }, () => {
      if (chrome.runtime.lastError) {
        console.error("[Malicious URL Detector] Could not continue to blocked URL:", chrome.runtime.lastError.message);
        sendResponse({ ok: false, error: chrome.runtime.lastError.message });
        return;
      }

      sendResponse({ ok: true });
    });

    return true;
  }

  if (message?.type === "dom-ready") {
    const tabId = sender.tab?.id;
    const targetUrl = message.url;
    const previous = tabRiskState.get(tabId);

    if (
      typeof tabId === "number" &&
      targetUrl &&
      previous?.url === targetUrl &&
      previous.riskLevel === "medium"
    ) {
      showCautionBanner(tabId, targetUrl, {
        confidence: previous.confidence,
        reasons: previous.reasons || [],
      });
    }

    sendResponse({ ok: true });
    return false;
  }

  if (message?.type === "analyze-page-dom") {
    const tabId = sender.tab?.id;
    const targetUrl = message.url;

    if (
      typeof tabId !== "number" ||
      !targetUrl ||
      shouldSkipUrl(targetUrl) ||
      isTrustedDomain(targetUrl) ||
      hasProceedOverride(tabId, targetUrl)
    ) {
      sendResponse({ ok: false, skipped: true });
      return false;
    }

    classifyUrl(targetUrl, message.domSignals || null)
      .then((result) => {
        handleRiskResult(tabId, targetUrl, result, "dom-assisted");
        sendResponse({ ok: true, risk_level: result.risk_level });
      })
      .catch((error) => {
        console.error("[Malicious URL Detector] DOM-assisted analysis failed:", error);
        sendResponse({ ok: false, error: error.message });
      });

    return true;
  }

  return false;
});

// Listen for main frame navigations before they fully commit
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only process the main frame (the main webpage), not embedded iframes
  if (details.frameId !== 0) return;

  const targetUrl = details.url;

  // Ignore internal Chrome pages, extension pages, and local IP to prevent loops
  if (shouldSkipUrl(targetUrl)) {
    return;
  }

  if (hasProceedOverride(details.tabId, targetUrl)) {
    console.log(`[Malicious URL Detector] Proceed override active for: ${targetUrl}`);
    return;
  }

  if (isTrustedDomain(targetUrl)) {
    console.log(`[Malicious URL Detector] Skipping trusted domain: ${targetUrl}`);
    return;
  }

  try {
    console.log("Sending request to backend:", targetUrl);
    const result = await classifyUrl(targetUrl);
    console.log("Backend response:", result);

    handleRiskResult(details.tabId, targetUrl, result);

  } catch (error) {
    // This catches network errors (e.g., backend server is not running)
    // We fail gracefully so the user can still browse the web normally
    console.error("[Malicious URL Detector] Could not connect to the backend server:", error);
  }
});
