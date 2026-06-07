import * as d3 from "d3";
import { useEffect, useMemo, useRef, useState } from "react";
import { getJson, severityClass, strongestDetection } from "../api.js";

const NODE_COLORS = {
  agent: "#38bdf8",
  tool: "#34d399",
  domain: "#94a3b8"
};

const LEGEND = [
  ["Agent", "#38bdf8"],
  ["Tool", "#34d399"],
  ["Flagged domain", "#f43f5e"],
  ["Domain", "#94a3b8"]
];

export default function TrustGraph({ sessionId, events, onEventSelect }) {
  const svgRef = useRef(null);
  const [graph, setGraph] = useState({ nodes: [], links: [] });
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    if (!sessionId) {
      setGraph({ nodes: [], links: [] });
      return;
    }
    getJson(`/api/graph/${sessionId}`).then(setGraph).catch(console.error);
  }, [sessionId, events.length]);

  useEffect(() => {
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    if (!graph.nodes.length) return undefined;

    const width = 860;
    const height = 560;
    const nodes = graph.nodes.map((node) => ({ ...node }));
    const links = graph.links.map((link) => ({ ...link }));

    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const defs = svg.append("defs");
    const glow = defs.append("filter").attr("id", "node-glow").attr("x", "-60%").attr("y", "-60%").attr("width", "220%").attr("height", "220%");
    glow.append("feGaussianBlur").attr("stdDeviation", "5").attr("result", "blur");
    const merge = glow.append("feMerge");
    merge.append("feMergeNode").attr("in", "blur");
    merge.append("feMergeNode").attr("in", "SourceGraphic");

    const nodeColor = (item) =>
      item.type === "domain" && item.threat_score > 0 ? "#f43f5e" : NODE_COLORS[item.type] || "#64748b";
    const linkColor = (edge) => {
      const score = edge.threat_score || 0;
      if (score >= 95) return "#f43f5e";
      if (score >= 70) return "#f59e0b";
      if (score >= 40) return "#eab308";
      return "#3b4d6b";
    };

    const simulation = d3
      .forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((node) => node.id).distance(135))
      .force("charge", d3.forceManyBody().strength(-520))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(50));

    const link = svg
      .append("g")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke", linkColor)
      .attr("stroke-opacity", (edge) => (edge.threat_score > 0 ? 0.85 : 0.4))
      .attr("stroke-width", (edge) => Math.max(1.5, Math.sqrt(edge.call_frequency || 1) * 2.2));

    const node = svg
      .append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .attr("cursor", "pointer")
      .call(
        d3
          .drag()
          .on("start", (event) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
          })
          .on("drag", (event) => {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
          })
          .on("end", (event) => {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
          })
      )
      .on("click", (_, nodeData) => setSelectedNode(nodeData));

    node
      .append("circle")
      .attr("r", 26)
      .attr("fill", nodeColor)
      .attr("fill-opacity", 0.16)
      .attr("stroke", nodeColor)
      .attr("stroke-width", 1.4)
      .attr("stroke-opacity", 0.55);

    node
      .append("circle")
      .attr("r", 13)
      .attr("fill", nodeColor)
      .attr("filter", "url(#node-glow)");

    node
      .append("text")
      .text((item) => item.label)
      .attr("dy", 44)
      .attr("text-anchor", "middle")
      .attr("fill", "#cbd5e1")
      .attr("font-size", 12)
      .attr("font-weight", 600)
      .attr("paint-order", "stroke")
      .attr("stroke", "#05080f")
      .attr("stroke-width", 3);

    simulation.on("tick", () => {
      link
        .attr("x1", (edge) => edge.source.x)
        .attr("y1", (edge) => edge.source.y)
        .attr("x2", (edge) => edge.target.x)
        .attr("y2", (edge) => edge.target.y);

      node.attr("transform", (item) => `translate(${item.x},${item.y})`);
    });

    return () => simulation.stop();
  }, [graph]);

  const relatedEvents = useMemo(() => {
    if (!selectedNode) return [];
    return events.filter((event) => isEventRelated(event, selectedNode));
  }, [events, selectedNode]);

  return (
    <section className="glass overflow-hidden rounded-2xl">
      <div className="flex items-center justify-between border-b border-white/5 px-5 py-4">
        <div>
          <p className="text-[11px] uppercase tracking-[0.3em] text-slate-500">Per-session topology</p>
          <h2 className="text-lg font-bold text-white">Trust Graph</h2>
        </div>
        <div className="flex flex-wrap gap-3 text-[11px] text-slate-400">
          {LEGEND.map(([label, color]) => (
            <span key={label} className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
              {label}
            </span>
          ))}
        </div>
      </div>

      <div className="grid gap-4 p-4 lg:grid-cols-[1fr_280px]">
        <div className="relative min-h-[560px] overflow-hidden rounded-xl border border-white/8 bg-[#070c17]">
          <div className="pointer-events-none absolute inset-0 opacity-60" style={{ backgroundImage: "radial-gradient(circle at 50% 40%, rgba(56,189,248,0.08), transparent 60%)" }} />
          {!graph.nodes.length && (
            <div className="absolute inset-0 grid place-items-center text-sm text-slate-500">
              Select a session to render its trust graph.
            </div>
          )}
          <svg ref={svgRef} className="relative h-full min-h-[560px] w-full" />
        </div>

        <div className="flex max-h-[560px] flex-col rounded-xl border border-white/8 bg-white/[0.02] p-3">
          <h3 className="font-semibold text-white">{selectedNode?.label || "Inspect a node"}</h3>
          <p className="mt-1 text-xs text-slate-500">
            {selectedNode
              ? `${relatedEvents.length} related event${relatedEvents.length === 1 ? "" : "s"}`
              : "Click any agent, tool, or domain to see its traffic."}
          </p>
          <div className="scroll-thin mt-3 flex-1 space-y-2 overflow-y-auto">
            {relatedEvents.map((event) => {
              const detection = strongestDetection(event);
              return (
                <button
                  key={event.id}
                  onClick={() => onEventSelect(event)}
                  className={`w-full rounded-lg border p-2.5 text-left text-xs transition hover:brightness-125 ${severityClass(detection?.severity)}`}
                >
                  <div className="flex justify-between">
                    <span className="font-mono font-semibold">{event.tool_name}</span>
                    <span className="font-bold">{detection?.severity || "CLEAN"}</span>
                  </div>
                  <p className="mt-1 line-clamp-2 opacity-90">{detection?.evidence || "No detector findings."}</p>
                </button>
              );
            })}
            {selectedNode && !relatedEvents.length && (
              <p className="rounded-lg border border-dashed border-white/10 p-3 text-center text-slate-500">
                No events for this node in the current view.
              </p>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

function isEventRelated(event, node) {
  if (node.type === "tool") return event.tool_name === node.label;
  const serializedArgs = JSON.stringify(event.arguments || {});
  if (node.type === "agent") return serializedArgs.includes(node.label);
  if (node.type === "domain") return serializedArgs.includes(node.label);
  return false;
}
