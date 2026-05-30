import React from 'react';
import { useSocketEvents } from './hooks/useSocketEvents';
import { useShadowStore } from './store/useShadowStore';
import StatsBar from './components/StatsBar';
import AlertFeed from './components/AlertFeed';
import NetworkGraph from './components/NetworkGraph';
import DemoControlBar from './components/DemoControlBar';
import ErrorBoundary from './components/ErrorBoundary';
import AttackerList from './components/AttackerList';
import AttackerProfile from './components/AttackerProfile';
import { motion, AnimatePresence } from 'framer-motion';
// import MitreHeatmap from './components/MitreHeatmap';

function App() {
  const { isConnected } = useSocketEvents();
  const isDeceptionActive = useShadowStore(state => state.isDeceptionActive);

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
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-shadowGreen' : 'bg-shadowRed'}`}></div>
          <span className="text-gray-400 text-sm">{isConnected ? 'System Online' : 'Disconnected'}</span>
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
        <aside className="w-80 flex flex-col bg-[#0d0d0d]">
          <div className="flex-1 border-b border-[#2a2a2a] p-4 overflow-hidden">
            <AlertFeed />
          </div>
          <div className="h-64 p-4 text-gray-500 text-sm border-t border-[#2a2a2a] flex items-center justify-center bg-[#161616]">
            {/* <MitreHeatmap /> */}
            MitreHeatmap Placeholder
          </div>
        </aside>
      </main>
    </div>
  );
}

export default App;
