import { Icon } from "./icons.jsx";

export default function ThreatStats({ stats }) {
  const cards = [
    {
      label: "Calls Intercepted",
      value: stats.total_calls ?? 0,
      icon: "intercept",
      accent: "text-cyan-300",
      glow: "from-cyan-500/15",
      ring: "border-cyan-500/20"
    },
    {
      label: "Threats Detected",
      value: stats.threats_detected ?? 0,
      icon: "threat",
      accent: "text-amber-300",
      glow: "from-amber-500/15",
      ring: "border-amber-500/20"
    },
    {
      label: "Critical Alerts",
      value: stats.critical_alerts ?? 0,
      icon: "critical",
      accent: "text-rose-300",
      glow: "from-rose-500/15",
      ring: "border-rose-500/25"
    },
    {
      label: "Clean Sessions",
      value: `${stats.clean_sessions_percent ?? 100}%`,
      icon: "clean",
      accent: "text-emerald-300",
      glow: "from-emerald-500/15",
      ring: "border-emerald-500/20"
    }
  ];

  return (
    <section className="grid grid-cols-2 gap-4 md:grid-cols-4">
      {cards.map((card) => (
        <div
          key={card.label}
          className={`glass glass-hover relative overflow-hidden rounded-2xl border ${card.ring} p-4`}
        >
          <div
            className={`pointer-events-none absolute -right-6 -top-10 h-28 w-28 rounded-full bg-gradient-to-b ${card.glow} to-transparent blur-2xl`}
          />
          <div className="relative flex items-start justify-between">
            <div>
              <p className="text-[11px] font-medium uppercase tracking-[0.18em] text-slate-400">
                {card.label}
              </p>
              <p className="mt-2 text-4xl font-bold tracking-tight text-white">{card.value}</p>
            </div>
            <div className={`grid h-9 w-9 place-items-center rounded-lg border border-white/10 bg-white/5 ${card.accent}`}>
              <Icon name={card.icon} className="h-5 w-5" />
            </div>
          </div>
        </div>
      ))}
    </section>
  );
}
