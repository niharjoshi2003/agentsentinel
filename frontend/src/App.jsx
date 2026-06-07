import { useEffect, useState } from "react";
import EventDrawer from "./components/EventDrawer.jsx";
import LiveThreatFeed from "./components/LiveThreatFeed.jsx";
import SessionPanel from "./components/SessionPanel.jsx";
import ThreatStats from "./components/ThreatStats.jsx";
import TrustGraph from "./components/TrustGraph.jsx";
import { ShieldLogo } from "./components/icons.jsx";
import { getJson, postJson } from "./api.js";

export default function App() {
  const [sessions, setSessions] = useState([]);
  const [stats, setStats] = useState({});
  const [selectedSession, setSelectedSession] = useState(null);
  const [events, setEvents] = useState([]);
  const [drawerEvent, setDrawerEvent] = useState(null);
  const [demoRunning, setDemoRunning] = useState(false);

  async function runDemo() {
    if (demoRunning) return;
    setDemoRunning(true);
    try {
      await postJson("/api/demo/run");
    } catch (error) {
      console.error(error);
    }
    setTimeout(() => setDemoRunning(false), 11000);
  }

  useEffect(() => {
    let cancelled = false;

    async function loadSessions() {
      const data = await getJson("/api/sessions");
      if (cancelled) return;
      setSessions(data.sessions || []);
      setStats(data.stats || {});
      if (!selectedSession && data.sessions?.length) {
        setSelectedSession(data.sessions[0].session_id);
      }
    }

    loadSessions().catch(console.error);
    const interval = setInterval(() => loadSessions().catch(console.error), 2500);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [selectedSession]);

  useEffect(() => {
    if (!selectedSession) {
      setEvents([]);
      return;
    }

    let cancelled = false;
    async function loadEvents() {
      const data = await getJson(`/api/session/${selectedSession}/events`);
      if (!cancelled) {
        setEvents(data.events || []);
      }
    }

    loadEvents().catch(console.error);
    const interval = setInterval(() => loadEvents().catch(console.error), 2500);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [selectedSession]);

  return (
    <div className="grid-overlay relative min-h-screen text-slate-100">
      <div className="relative z-10 flex">
        <SessionPanel
          sessions={sessions}
          selectedSession={selectedSession}
          onSelectSession={setSelectedSession}
        />

        <main className="flex-1 px-6 pb-8">
          <header className="sticky top-0 z-20 -mx-6 mb-6 border-b border-white/5 bg-[#05080f]/70 px-6 py-4 backdrop-blur-xl">
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="grid h-11 w-11 place-items-center rounded-xl border border-cyan-400/20 bg-cyan-400/5">
                  <ShieldLogo size={26} />
                </div>
                <div>
                  <p className="text-[11px] font-semibold uppercase tracking-[0.4em] text-cyan-300/80">
                    Runtime MCP Defense
                  </p>
                  <h1 className="text-2xl font-bold leading-tight title-gradient">AgentSentinel</h1>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={runDemo}
                  disabled={demoRunning}
                  className="flex items-center gap-2 rounded-full border border-cyan-400/40 bg-cyan-400/15 px-4 py-1.5 text-sm font-semibold text-cyan-100 transition hover:bg-cyan-400/25 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <span className={`h-2 w-2 rounded-full bg-cyan-300 ${demoRunning ? "live-dot" : ""}`} />
                  {demoRunning ? "Running attacks…" : "Run demo attacks"}
                </button>
                <div className="hidden items-center gap-2 rounded-full border border-emerald-400/25 bg-emerald-400/10 px-3 py-1.5 text-xs font-medium text-emerald-300 sm:flex">
                  <span className="live-dot h-2 w-2 rounded-full bg-emerald-400" />
                  Monitoring live
                </div>
                <div className="hidden max-w-[220px] truncate rounded-full border border-cyan-400/25 bg-cyan-400/10 px-4 py-1.5 text-sm text-cyan-100 lg:block">
                  {selectedSession || "waiting for sessions"}
                </div>
              </div>
            </div>
          </header>

          <ThreatStats stats={stats} />

          <div className="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-[1fr_400px]">
            <TrustGraph
              sessionId={selectedSession}
              events={events}
              onEventSelect={setDrawerEvent}
            />
            <LiveThreatFeed
              selectedSession={selectedSession}
              onThreatSelect={setDrawerEvent}
              onSessionSeen={setSelectedSession}
            />
          </div>
        </main>
      </div>

      <EventDrawer event={drawerEvent} onClose={() => setDrawerEvent(null)} />
    </div>
  );
}
