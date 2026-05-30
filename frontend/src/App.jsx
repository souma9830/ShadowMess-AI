import React, { useEffect } from 'react';
import { useSocketEvents } from './hooks/useSocketEvents';
import { useShadowStore } from './store/useShadowStore';
import StatsBar from './components/StatsBar';
import AlertFeed from './components/AlertFeed';
import NetworkGraph from './components/NetworkGraph';
import DemoControlBar from './components/DemoControlBar';
import ErrorBoundary from './components/ErrorBoundary';
import AttackerList from './components/AttackerList';
import AttackerProfile from './components/AttackerProfile';
import DnsIntelligence from './components/DnsIntelligence';
import MitreHeatmap from './components/MitreHeatmap';
import { motion, AnimatePresence } from 'framer-motion';

function App() {
  const { isConnected } = useSocketEvents();
  const isDeceptionActive = useShadowStore(state => state.isDeceptionActive);
  const activeBreadcrumbs = useShadowStore(state => state.activeBreadcrumbs);

  // Dwell time timer — ticks every second while deception is active
  useEffect(() => {
    if (!isDeceptionActive) return;
    const interval = setInterval(() => {
      useShadowStore.getState().incrementStat('dwellTimeSeconds');
    }, 1000);
    return () => clearInterval(interval);
  }, [isDeceptionActive]);

  // Hydrate state from backend on page load — restores graph, sessions,
  // profiles and DNS log after a browser refresh (backend still running).
  useEffect(() => {
    const hydrate = async () => {
      // 1. Restore topology
      let hasTopology = false;
      try {
        const res = await fetch('/api/topology/current');
        if (res.ok) {
          const topo = await res.json();
          if (topo.nodes?.length > 0) {
            useShadowStore.getState().updateTopology(topo.nodes, topo.edges, topo.generation);
            hasTopology = true;
          }
        }
      } catch {}

      // 2. Restore attacker sessions
      let sessions = [];
      try {
        const res = await fetch('/api/attackers');
        if (res.ok) {
          sessions = await res.json();
          for (const s of sessions) {
            useShadowStore.getState().updateSession(s.ip, s);
          }
          // Only mark deception active if there's also a topology to show
          if (sessions.length > 0 && hasTopology) {
            const latest = [...sessions].sort(
              (a, b) => (b.last_seen || 0) - (a.last_seen || 0)
            )[0];
            useShadowStore.getState().activateDeception(latest.ip);
            useShadowStore.getState().setFocusedAttacker(latest.ip);
          }
        }
      } catch {}

      // 3. Restore profiles — fetch all in parallel then set in one call
      if (sessions.length > 0) {
        const entries = await Promise.all(
          sessions.map(async (s) => {
            try {
              const res = await fetch(`/api/attacker/profile/${s.ip}`);
              if (res.ok) {
                const profile = await res.json();
                return [s.ip, profile];
              }
            } catch {}
            return null;
          })
        );
        const profiles = Object.fromEntries(entries.filter(Boolean));
        if (Object.keys(profiles).length > 0) {
          useShadowStore.getState().setAttackerProfiles(profiles);
        }
      }

      // 4. Restore DNS query log (oldest-first from API → addDnsQuery prepends → newest at top)
      try {
        const res = await fetch('/api/dns/queries');
        if (res.ok) {
          const queries = await res.json();
          for (const q of queries.slice(-10)) {
            useShadowStore.getState().addDnsQuery(q);
          }
        }
      } catch {}
    };

    hydrate();
  }, []); // runs once on mount

  return (
    <div className="flex flex-col h-screen overflow-hidden text-white bg-[#0d0d0d]">
      {/* Top Nav */}
      <header 
        className={`h-14 border-b border-[#2a2a2a] flex items-center justify-between px-6 transition-colors duration-1000 ${
          isDeceptionActive ? 'bg-[#E24B4A]/10 border-b-[#E24B4A]/30' : 'bg-[#0d0d0d]'
        }`}
      >
        <div className="text-white text-lg font-bold tracking-wide">
          <span className="text-shadowRed">Shadow</span>Mesh
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-shadowGreen' : 'bg-shadowRed'}`}></div>
            <span className="text-gray-400 text-sm">{isConnected ? 'System Online' : 'Disconnected'}</span>
          </div>
          {activeBreadcrumbs > 0 && (
            <div className="flex items-center gap-1.5 px-2 py-0.5 bg-shadowGreen/20 border border-shadowGreen/40 rounded-full">
              <span className="w-1.5 h-1.5 bg-shadowGreen rounded-full animate-pulse"></span>
              <span className="text-[10px] text-shadowGreen font-bold uppercase tracking-wide">
                Agents: {activeBreadcrumbs} Active
              </span>
            </div>
          )}
        </div>
        <div className="text-sm font-mono h-8 flex items-center min-w-[320px] justify-end">
          <AnimatePresence mode="wait">
            {!isDeceptionActive ? (
              <motion.span 
                key="monitoring"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-gray-400"
              >
                MONITORING
              </motion.span>
            ) : (
              <motion.span 
                key="active"
                initial={{ width: 0, opacity: 0 }}
                animate={{ width: 'auto', opacity: 1 }}
                className="text-shadowRed font-bold flex overflow-hidden whitespace-nowrap drop-shadow-[0_0_5px_rgba(226,75,74,0.5)]"
              >
                THREAT ACTIVE — DECEPTION FABRIC ONLINE
              </motion.span>
            )}
          </AnimatePresence>
        </div>
      </header>
      
      {/* Main content with grid background */}
      <main 
        className="flex flex-1 overflow-hidden relative"
        style={{
          backgroundImage: 'linear-gradient(#ffffff05 1px, transparent 1px), linear-gradient(90deg, #ffffff05 1px, transparent 1px)',
          backgroundSize: '40px 40px'
        }}
      >
        {/* Socket Disconnect Toast */}
        <AnimatePresence>
          {!isConnected && (
            <motion.div 
              initial={{ y: -50, opacity: 0, x: '-50%' }}
              animate={{ y: 16, opacity: 1, x: '-50%' }}
              exit={{ y: -50, opacity: 0, x: '-50%' }}
              className="absolute top-0 left-1/2 bg-shadowRed text-white px-4 py-2 rounded-lg shadow-lg shadow-shadowRed/20 z-50 font-bold tracking-wide"
            >
              Backend connection lost — reconnecting...
            </motion.div>
          )}
        </AnimatePresence>
        {/* Left Sidebar */}
        <aside className="w-80 border-r border-[#2a2a2a] p-4 flex flex-col gap-4 bg-[#0d0d0d] overflow-y-auto z-10">
          <div className="shrink-0 h-32 border border-[#2a2a2a] rounded-lg bg-[#161616]">
            <StatsBar />
          </div>
          <div className="shrink-0 max-h-48 border border-[#2a2a2a] rounded-lg bg-[#161616]">
            <AttackerList />
          </div>
          <div className="flex-1 border border-[#2a2a2a] rounded-lg bg-[#161616] overflow-hidden">
            <ErrorBoundary componentName="AttackerProfile">
              <AttackerProfile />
            </ErrorBoundary>
          </div>
        </aside>
        
        {/* Center Panel */}
        <section className="flex-1 bg-transparent flex flex-col relative border-r border-[#2a2a2a]">
          <ErrorBoundary componentName="Network Graph">
            <NetworkGraph />
          </ErrorBoundary>
          <DemoControlBar />
        </section>
        
        {/* Right Sidebar */}
        <aside className="w-80 flex flex-col bg-[#0d0d0d] border-l border-[#2a2a2a] z-10">
          <div className="flex-1 overflow-hidden">
            <ErrorBoundary componentName="AlertFeed">
              <AlertFeed />
            </ErrorBoundary>
          </div>
          <div className="h-64 shrink-0 overflow-hidden">
            <ErrorBoundary componentName="DnsIntelligence">
              <DnsIntelligence />
            </ErrorBoundary>
          </div>
          <div className="h-64 shrink-0 overflow-hidden">
            <ErrorBoundary componentName="MitreHeatmap">
              <MitreHeatmap />
            </ErrorBoundary>
          </div>
        </aside>
      </main>
    </div>
  );
}

export default App;
