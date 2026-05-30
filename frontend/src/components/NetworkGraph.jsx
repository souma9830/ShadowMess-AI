import React, { useRef, useEffect, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { useShadowStore } from '../store/useShadowStore';
import { useShallow } from 'zustand/react/shallow';
import { motion } from 'framer-motion';

export default function NetworkGraph() {
  const { nodes, edges, isMutating, actions } = useShadowStore(
    useShallow(state => ({
      nodes: state.nodes,
      edges: state.edges,
      isMutating: state.isMutating,
      actions: state.actions,
    }))
  );
  const graphRef = useRef();
  const [hoverNode, setHoverNode] = useState(null);

  const graphData = {
    nodes: nodes.map(n => ({
      id: n.node_id,
      ip: n.ip,
      nodeType: n.node_type,
      ports: n.ports,
      banner: n.banner,
      os: n.os,
      container_id: n.container_id
    })),
    links: edges.map(([src, tgt]) => ({ source: src, target: tgt }))
  };

  const getNodeColor = (nodeType) => {
    switch(nodeType) {
      case 'web_server': return '#1D9E75';
      case 'db_server': return '#E24B4A';
      case 'auth_service': return '#7F77DD';
      case 'file_server': return '#EF9F27';
      case 'api_gateway': return '#378ADD';
      case 'mail_server': return '#D4537E';
      case 'workstation': return '#888780';
      default: return '#888780';
    }
  };

  useEffect(() => {
    if (graphRef.current) {
      graphRef.current.d3AlphaDecay(isMutating ? 0.5 : 0.02);
      if (!isMutating) {
        graphRef.current.d3ReheatSimulation();
      }
    }
  }, [isMutating]);

  useEffect(() => {
    const style = document.createElement('style');
    style.innerHTML = `
      @keyframes scanline { from { top: 0% } to { top: 100% } }
      .animate-scanline { animation: scanline 0.8s linear infinite; }
    `;
    document.head.appendChild(style);
    return () => document.head.removeChild(style);
  }, []);

  return (
    <div className="w-full h-full relative overflow-hidden bg-[#0d0d0d]">
      <motion.div 
        className="w-full h-full"
        animate={{ 
          filter: isMutating ? 'blur(4px)' : 'blur(0px)', 
          opacity: isMutating ? 0.4 : 1 
        }}
        transition={{ duration: 0.3 }}
      >
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          backgroundColor="#0d0d0d"
          linkColor={() => '#2a2a2a'}
          linkWidth={1}
          d3AlphaDecay={0.02}
          cooldownTicks={150}
          nodePointerAreaPaint={(node, color, ctx) => {
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(node.x, node.y, 12, 0, 2 * Math.PI);
            ctx.fill();
          }}
          nodeCanvasObject={(node, ctx, globalScale) => {
            const hasBeenHit = actions.some(a => a.target_node_id === node.id);
            const baseColor = getNodeColor(node.nodeType);
            
            if (hasBeenHit) {
              ctx.beginPath();
              ctx.arc(node.x, node.y, 11, 0, 2 * Math.PI);
              ctx.fillStyle = baseColor;
              ctx.globalAlpha = 0.3;
              ctx.fill();
              ctx.globalAlpha = 1;
            }

            ctx.beginPath();
            ctx.arc(node.x, node.y, 8, 0, 2 * Math.PI);
            ctx.fillStyle = isMutating ? '#ffffff' : baseColor;
            ctx.fill();

            const label = node.ip;
            const fontSize = 10 / globalScale;
            ctx.font = `${fontSize}px monospace`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
            ctx.fillText(label, node.x, node.y + 14);
          }}
          onNodeHover={setHoverNode}
        />
      </motion.div>

      {/* Tooltip */}
      {hoverNode && (
        <div 
          className="absolute bg-[#1a1a1a] border border-[#333] text-white p-3 rounded-lg shadow-xl text-xs pointer-events-none z-10"
          style={{ top: 16, left: 16 }}
        >
          <div className="font-mono font-bold text-shadowGreen mb-1">{hoverNode.ip}</div>
          <div className="text-gray-400">Type: <span className="text-white">{hoverNode.nodeType}</span></div>
          <div className="text-gray-400">Ports: <span className="text-white">{hoverNode.ports?.join(', ')}</span></div>
          <div className="text-gray-400">OS: <span className="text-white">{hoverNode.os}</span></div>
          <div className="text-gray-400">Banner: <span className="text-white">{hoverNode.banner}</span></div>
          {hoverNode.container_id && (
            <div className="text-gray-500 mt-1 font-mono text-[10px]">CID: {hoverNode.container_id.substring(0,8)}</div>
          )}
        </div>
      )}

      {/* Cinematic Mutation Overlay */}
      {isMutating && (
        <div className="absolute inset-0 pointer-events-none flex items-center justify-center">
          <div className="text-shadowRed font-mono text-2xl font-bold tracking-widest animate-pulse drop-shadow-[0_0_10px_rgba(226,75,74,0.8)] z-20 bg-black/50 px-4 py-2 rounded">
            TOPOLOGY RESHUFFLING
          </div>
          <div className="absolute left-0 right-0 h-[2px] bg-shadowRed shadow-[0_0_8px_#E24B4A] animate-scanline z-10" />
        </div>
      )}
    </div>
  );
}
