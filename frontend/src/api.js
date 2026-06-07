export async function getJson(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

export async function postJson(path, payload = {}) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

export function strongestDetection(event) {
  const detections = event?.detector_results || [];
  return detections.reduce((best, item) => ((item.score || 0) > (best?.score || 0) ? item : best), detections[0]);
}

export function severityClass(severity) {
  switch (severity) {
    case "CRITICAL":
      return "bg-rose-500/12 text-rose-200 border-rose-500/40";
    case "HIGH":
      return "bg-amber-500/12 text-amber-200 border-amber-500/40";
    case "MEDIUM":
      return "bg-yellow-500/12 text-yellow-100 border-yellow-500/35";
    case "LOW":
      return "bg-slate-500/12 text-slate-300 border-slate-500/35";
    default:
      return "bg-emerald-500/12 text-emerald-200 border-emerald-500/40";
  }
}

const SEV_META = {
  CRITICAL: { dot: "#f43f5e", text: "text-rose-300", ring: "ring-rose-500/40", label: "Critical" },
  HIGH: { dot: "#f59e0b", text: "text-amber-300", ring: "ring-amber-500/40", label: "High" },
  MEDIUM: { dot: "#eab308", text: "text-yellow-300", ring: "ring-yellow-500/40", label: "Medium" },
  LOW: { dot: "#64748b", text: "text-slate-300", ring: "ring-slate-500/40", label: "Low" },
  CLEAN: { dot: "#22c55e", text: "text-emerald-300", ring: "ring-emerald-500/40", label: "Clean" }
};

export function severityMeta(severity) {
  return SEV_META[severity] || SEV_META.CLEAN;
}

export function scoreColor(score) {
  if (score >= 95) return "#f43f5e";
  if (score >= 70) return "#f59e0b";
  if (score >= 40) return "#eab308";
  if (score > 0) return "#64748b";
  return "#22c55e";
}
