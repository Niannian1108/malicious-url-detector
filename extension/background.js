const API_URL = "http://127.0.0.1:8000/predict";
const BLOCK_CONFIDENCE_THRESHOLD = 0.95;

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

// Listen for main frame navigations before they fully commit
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only process the main frame (the main webpage), not embedded iframes
  if (details.frameId !== 0) return;

  const targetUrl = details.url;

  // Ignore internal Chrome pages, extension pages, and local IP to prevent loops
  if (
    targetUrl.startsWith("chrome://") ||
    targetUrl.startsWith("chrome-extension://") ||
    targetUrl.startsWith("about:") ||
    targetUrl.includes("127.0.0.1") ||
    targetUrl.includes("localhost")
  ) {
    return;
  }

  if (isTrustedDomain(targetUrl)) {
    console.log(`[Malicious URL Detector] Skipping trusted domain: ${targetUrl}`);
    return;
  }

  try {
    // Send the URL to our local backend for classification
    console.log("Sending request to backend:", targetUrl);
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: targetUrl }),
    });

    if (!response.ok) {
      console.warn(`[Malicious URL Detector] API error: ${response.status} ${response.statusText}`);
      return; // Fail open (allow navigation) if server throws error
    }

    const result = await response.json();
    console.log("Backend response:", result);

    // Only hard-block very high-confidence detections while the model is
    // still being tuned to reduce false positives.
    if (result.prediction === 1 && result.confidence >= BLOCK_CONFIDENCE_THRESHOLD) {
      console.warn(`[Malicious URL Detector] Blocked URL: ${targetUrl} (Confidence: ${result.confidence})`);

      // Redirect the tab immediately to a safe page like about:blank
      chrome.tabs.update(details.tabId, { url: "about:blank" });

      // Create a system notification to inform the user
      chrome.notifications.create({
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/icon128.png"),
        title: "Danger: Malicious Website Blocked!",
        message: `We stopped you from visiting a dangerous site.\nConfidence: ${result.confidence}`,
        priority: 2
      }, () => {
        if (chrome.runtime.lastError) {
          console.error("Notification error:", chrome.runtime.lastError.message);
        }
      });
    } else if (result.prediction === 1) {
      console.warn(
        `[Malicious URL Detector] Suspicious URL allowed due to low confidence: ${targetUrl} ` +
        `(Confidence: ${result.confidence})`
      );
    } else {
      console.log(`[Malicious URL Detector] URL is safe: ${targetUrl}`);
    }

  } catch (error) {
    // This catches network errors (e.g., backend server is not running)
    // We fail gracefully so the user can still browse the web normally
    console.error("[Malicious URL Detector] Could not connect to the backend server:", error);
  }
});
