import { useEffect, useRef, useState } from "react";
import { severityMeta, strongestDetection } from "../api.js";

export default function LiveThreatFeed({ selectedSession, onThreatSelect, onSessionSeen }) {
  const [threats, setThreats] = useState([]);
  const [connected, setConnected] = useState(false);
  const listRef = useRef(null);

  useEffect(() => {
    const source = new EventSource("/api/threats/live");
    source.onopen = () => setConnected(true);
    source.onmessage = (message) => {
      const event = JSON.parse(message.data);
      setThreats((items) => [event, ...items].slice(0, 100));
      onSessionSeen?.(event.session_id);
    };
    source.onerror = () => {
      setConnected(false);
      source.close();
    };
    return () => source.close();
  }, [onSessionSeen]);

  useEffect(() => {
    if (listRef.current) {
      listRef.current.scrollTop = 0;
    }
  }, [threats.length]);

  const visibleThreats = selectedSession
    ? threats.filter((event) => event.session_id === selectedSession)
    : threats;

  return (
    <section className="glass flex max-h-[760px] flex-col overflow-hidden rounded-2xl">
      <div className="flex items-center justify-between border-b border-white/5 px-5 py-4">
        <div>
          <p className="text-[11px] uppercase tracking-[0.3em] text-slate-500">Server-Sent Events</p>
          <h2 className="text-lg font-bold text-white">Live Threat Feed</h2>
        </div>
        <span
          className={`flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium ${
            connected
              ? "border border-emerald-400/25 bg-emerald-400/10 text-emerald-300"
              : "border border-slate-500/25 bg-slate-500/10 text-slate-400"
          }`}
        >
          <span className={`h-2 w-2 rounded-full ${connected ? "live-dot bg-emerald-400" : "bg-slate-500"}`} />
          {connected ? "LIVE" : "offline"}
        </span>
      </div>

      <div ref={listRef} className="scroll-thin flex-1 space-y-2.5 overflow-y-auto p-4">
        {visibleThreats.map((event) => {
          const detection = strongestDetection(event);
          const sev = detection?.severity || "CLEAN";
          const meta = severityMeta(sev);
          return (
            <button
              key={event.id}
              onClick={() => onThreatSelect(event)}
              className={`sev-accent sev-${sev} animate-in glass-hover w-full rounded-xl border border-white/8 bg-white/[0.02] p-3 pl-4 text-left`}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full" style={{ background: meta.dot, boxShadow: `0 0 8px ${meta.dot}` }} />
                  <span className="font-mono text-sm font-semibold text-slate-100">{event.tool_name}</span>
                </div>
                <span className={`text-[10px] font-bold uppercase tracking-wider ${meta.text}`}>{sev}</span>
              </div>
              <p className="mt-1.5 text-[13px] font-medium text-slate-300">{detection?.threat_type}</p>
              <p className="mt-1.5 line-clamp-2 text-xs leading-relaxed text-slate-400">
                <span className={`font-semibold ${meta.text}`}>
                  {Math.round((detection?.confidence || 0) * 100)}%
                </span>{" "}
                {detection?.evidence}
              </p>
            </button>
          );
        })}
        {!visibleThreats.length && (
          <div className="grid h-full min-h-[200px] place-items-center rounded-xl border border-dashed border-white/10 p-6 text-center text-sm text-slate-500">
            <div>
              <p>Listening for detector alerts…</p>
              <p className="mt-1 text-xs">Threats appear here the moment they're intercepted.</p>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
