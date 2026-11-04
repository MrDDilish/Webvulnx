const form = document.getElementById("scanForm");
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const message = document.getElementById("message");
  message.textContent = "Submitting assessment...";
  try {
    const response = await fetch("/api/scans", {
      method: "POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({target: document.getElementById("target").value})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Unable to start scan");
    message.textContent = `Scan ${data.scan_id} queued. Refresh the page in a few seconds to see its status.`;
    setTimeout(() => location.reload(), 2500);
  } catch (err) { message.textContent = err.message; }
});

async function showFindings(id) {
  const panel = document.getElementById("findingsPanel");
  const target = document.getElementById("findings");
  panel.hidden = false;
  target.textContent = "Loading findings...";
  const res = await fetch(`/api/scans/${id}/findings`);
  const data = await res.json();
  target.innerHTML = "";
  if (!data.length) { target.textContent = "No findings recorded yet, or scan is still running."; return; }
  for (const f of data) {
    const item = document.createElement("article");
    item.className = "finding";
    const title = document.createElement("h3"); title.textContent = f.title;
    const sev = document.createElement("span"); sev.className = `sev ${f.severity}`; sev.textContent = `${f.severity} · ${f.category}`;
    const evidence = document.createElement("p"); evidence.textContent = `Evidence: ${f.evidence || "Not provided"}`;
    const fix = document.createElement("p"); fix.textContent = `Remediation: ${f.remediation || "Review manually"}`;
    item.append(sev,title,evidence,fix); target.append(item);
  }
  panel.scrollIntoView({behavior:"smooth"});
}
