const params = new URLSearchParams(window.location.search);
const targetUrl = params.get("url") || "";
const confidence = Number(params.get("confidence"));
const riskLevel = (params.get("risk") || "high").toLowerCase();
const reasons = params.getAll("reason");

const blockedUrlEl = document.getElementById("blockedUrl");
const confidenceValueEl = document.getElementById("confidenceValue");
const statusTextEl = document.getElementById("statusText");
const decisionValueEl = document.getElementById("decisionValue");
const headlineEl = document.getElementById("headline");
const subheadEl = document.getElementById("subhead");
const reasonsListEl = document.getElementById("reasonsList");
const goBackButton = document.getElementById("goBackButton");
const proceedButton = document.getElementById("proceedButton");

blockedUrlEl.textContent = targetUrl || "Unknown destination";
confidenceValueEl.textContent = Number.isFinite(confidence)
  ? `${Math.round(confidence * 100)}%`
  : "Unknown";
decisionValueEl.textContent = riskLevel === "high" ? "Blocked" : "Caution";
headlineEl.textContent = riskLevel === "high" ? "This site looks risky." : "This site deserves caution.";
subheadEl.textContent = riskLevel === "high"
  ? "The extension stopped this page because the detector scored it as high risk."
  : "The extension paused here because the detector found enough risk indicators to warn you.";

if (reasonsListEl) {
  const items = reasons.length
    ? reasons
    : ["The detector found a combination of URL and page signals that look suspicious."];

  reasonsListEl.replaceChildren(
    ...items.map((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      return item;
    })
  );
}

function setBusyState(isBusy, message = "") {
  goBackButton.disabled = isBusy;
  proceedButton.disabled = isBusy;
  statusTextEl.textContent = message;
}

goBackButton.addEventListener("click", async () => {
  try {
    if (window.history.length > 1) {
      window.history.back();
      return;
    }

    window.location.replace("about:blank");
  } catch (error) {
    console.error("[Malicious URL Detector] Go-back action failed:", error);
    statusTextEl.textContent = "Could not go back automatically. You can close this tab.";
  }
});

proceedButton.addEventListener("click", async () => {
  if (!targetUrl) {
    statusTextEl.textContent = "Missing blocked URL. Cannot continue.";
    return;
  }

  setBusyState(true, "Proceeding once to the blocked destination...");

  try {
    const result = await chrome.runtime.sendMessage({
      type: "proceed-once",
      url: targetUrl,
    });

    if (!result?.ok) {
      throw new Error(result?.error || "Unknown error");
    }
  } catch (error) {
    console.error("[Malicious URL Detector] Proceed action failed:", error);
    statusTextEl.textContent = "Could not continue to the site. Please try again.";
    goBackButton.disabled = false;
    proceedButton.disabled = false;
  }
});
