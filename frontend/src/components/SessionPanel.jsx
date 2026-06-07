import { ShieldLogo } from "./icons.jsx";
import { scoreColor } from "../api.js";

function ScoreRing({ score }) {
  const radius = 16;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(score, 100) / 100) * circumference;
  const color = scoreColor(score);
  return (
    <div className="relative grid h-11 w-11 place-items-center">
      <svg className="h-11 w-11 -rotate-90" viewBox="0 0 40 40">
        <circle cx="20" cy="20" r={radius} fill="none" stroke="rgba(148,163,184,0.18)" strokeWidth="3.5" />
        <circle
          cx="20"
          cy="20"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="3.5"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ filter: `drop-shadow(0 0 4px ${color}aa)`, transition: "stroke-dashoffset .5s ease" }}
        />
      </svg>
      <span className="absolute text-[11px] font-bold" style={{ color }}>
        {score}
      </span>
    </div>
  );
}

export default function SessionPanel({ sessions, selectedSession, onSelectSession }) {
  return (
    <aside className="sticky top-0 flex h-screen w-72 flex-col border-r border-white/5 bg-[#070b16]/80 backdrop-blur-xl">
      <div className="flex items-center gap-2.5 border-b border-white/5 px-5 py-[18px]">
        <ShieldLogo size={28} />
        <div>
          <p className="text-sm font-bold leading-tight text-white">AgentSentinel</p>
          <p className="text-[10px] uppercase tracking-[0.28em] text-slate-500">Sentinel SOC</p>
        </div>
      </div>

      <div className="px-5 pb-2 pt-4">
        <p className="text-[11px] uppercase tracking-[0.3em] text-slate-500">Monitored Sessions</p>
      </div>

      <div className="scroll-thin flex-1 space-y-2.5 overflow-y-auto px-4 pb-6">
        {sessions.map((session) => {
          const active = session.session_id === selectedSession;
          const score = session.max_threat_score ?? 0;
          return (
            <button
              key={session.session_id}
              onClick={() => onSelectSession(session.session_id)}
              className={`group w-full rounded-xl border p-3 text-left transition ${
                active
                  ? "border-cyan-400/60 bg-cyan-400/10 shadow-[0_0_0_1px_rgba(56,189,248,0.25)]"
                  : "border-white/8 bg-white/[0.02] hover:border-white/20 hover:bg-white/[0.04]"
              }`}
            >
              <div className="flex items-center gap-3">
                <ScoreRing score={score} />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-semibold text-slate-100">{session.session_id}</p>
                  <div className="mt-1 flex items-center gap-3 text-[11px] text-slate-400">
                    <span>{session.total_calls} calls</span>
                    <span className="h-1 w-1 rounded-full bg-slate-600" />
                    <span className={session.threats_detected > 0 ? "text-amber-300" : "text-emerald-300"}>
                      {session.threats_detected} threats
                    </span>
                  </div>
                </div>
              </div>
            </button>
          );
        })}
        {!sessions.length && (
          <div className="rounded-xl border border-dashed border-white/10 p-5 text-center text-sm text-slate-500">
            <p>No MCP traffic yet.</p>
            <p className="mt-1 text-xs">Run the demo attacks to populate.</p>
          </div>
        )}
      </div>

      <div className="border-t border-white/5 px-5 py-3 text-[10px] uppercase tracking-[0.2em] text-slate-600">
        Built by Nihar Joshi
      </div>
    </aside>
  );
}
