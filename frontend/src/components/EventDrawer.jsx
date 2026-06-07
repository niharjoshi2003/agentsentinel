import { postJson, severityMeta, severityClass, strongestDetection } from "../api.js";
import { Icon } from "./icons.jsx";

export default function EventDrawer({ event, onClose }) {
  const detection = strongestDetection(event);
  const sev = detection?.severity || "CLEAN";
  const meta = severityMeta(sev);

  async function markSafe() {
    if (!event) return;
    await postJson(`/api/events/${event.id}/mark-safe`);
    onClose();
  }

  async function blockTool() {
    if (!event) return;
    await postJson("/api/tools/block", { tool_name: event.tool_name });
  }

  return (
    <>
      <div
        onClick={onClose}
        className={`fixed inset-0 z-40 bg-black/60 backdrop-blur-sm transition-opacity duration-300 ${
          event ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
      />
      <div
        className={`fixed inset-y-0 right-0 z-50 w-full max-w-xl transform border-l border-white/10 bg-[#080d18] shadow-2xl transition-transform duration-300 ${
          event ? "translate-x-0" : "translate-x-full"
        }`}
      >
        {event && (
          <div className="drawer-in flex h-full flex-col">
            <div className="relative border-b border-white/8 p-5">
              <div
                className="pointer-events-none absolute inset-x-0 top-0 h-24"
                style={{ background: `radial-gradient(600px 120px at 30% -40%, ${meta.dot}33, transparent 70%)` }}
              />
              <div className="relative flex items-start justify-between gap-4">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.3em] text-slate-500">Event #{event.id}</p>
                  <h2 className="mt-1 font-mono text-2xl font-bold text-white">{event.tool_name}</h2>
                </div>
                <button
                  onClick={onClose}
                  className="grid h-9 w-9 place-items-center rounded-lg border border-white/10 bg-white/5 text-slate-300 transition hover:bg-white/10"
                >
                  <Icon name="close" className="h-4 w-4" />
                </button>
              </div>
              <div className={`relative mt-4 inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm ${severityClass(sev)}`}>
                <span className="h-2 w-2 rounded-full" style={{ background: meta.dot, boxShadow: `0 0 8px ${meta.dot}` }} />
                {sev} · {detection?.threat_type || "No threat detected"}
              </div>
            </div>

            <div className="scroll-thin flex-1 space-y-5 overflow-y-auto p-5">
              <section>
                <h3 className="mb-2 text-sm font-bold uppercase tracking-wider text-slate-400">Detector Reasoning</h3>
                <div className="space-y-2.5">
                  {(event.detector_results || []).map((result, index) => {
                    const rmeta = severityMeta(result.severity);
                    return (
                      <div
                        key={`${result.detector}-${index}`}
                        className={`sev-accent sev-${result.severity} rounded-xl border p-3 pl-4 text-sm ${severityClass(result.severity)}`}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-white">{result.detector}</span>
                          <span className={`text-xs font-bold ${rmeta.text}`}>
                            {Math.round(result.confidence * 100)}% confidence
                          </span>
                        </div>
                        <p className="mt-2 text-slate-200">{result.evidence}</p>
                        {result.metadata && Object.keys(result.metadata).length > 0 && (
                          <pre className="scroll-thin mt-2 max-h-32 overflow-auto rounded-lg bg-black/40 p-2 font-mono text-xs text-slate-300">
                            {JSON.stringify(result.metadata, null, 2)}
                          </pre>
                        )}
                      </div>
                    );
                  })}
                  {!event.detector_results?.length && (
                    <p className="rounded-xl border border-white/8 bg-white/[0.02] p-3 text-sm text-slate-400">
                      No detector findings for this event — clean passthrough.
                    </p>
                  )}
                </div>
              </section>

              <section>
                <h3 className="mb-2 text-sm font-bold uppercase tracking-wider text-slate-400">Full Payload</h3>
                <pre className="scroll-thin max-h-64 overflow-auto rounded-xl border border-white/8 bg-black/40 p-3 font-mono text-xs text-slate-200">
                  {JSON.stringify(event.arguments, null, 2)}
                </pre>
              </section>

              <section>
                <h3 className="mb-2 text-sm font-bold uppercase tracking-wider text-slate-400">Raw Evidence</h3>
                <pre className="scroll-thin max-h-64 overflow-auto whitespace-pre-wrap rounded-xl border border-white/8 bg-black/40 p-3 font-mono text-xs text-slate-200">
                  {event.raw_response}
                </pre>
              </section>
            </div>

            <div className="flex gap-3 border-t border-white/8 p-5">
              <button
                onClick={markSafe}
                className="flex-1 rounded-xl bg-emerald-500 px-4 py-3 font-semibold text-slate-950 transition hover:bg-emerald-400"
              >
                Mark Safe
              </button>
              <button
                onClick={blockTool}
                className="flex-1 rounded-xl bg-rose-500 px-4 py-3 font-semibold text-white transition hover:bg-rose-400"
              >
                Block Tool
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
