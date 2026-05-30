import React from 'react';

function App() {
  return (
    <div className="flex flex-col h-screen overflow-hidden text-white">
      {/* Top Nav */}
      <header className="h-14 border-b border-[#2a2a2a] flex items-center justify-between px-6 bg-[#0d0d0d]">
        <div className="text-white text-base font-bold">ShadowMesh</div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-gray-500"></div>
          <span className="text-gray-400 text-sm">Monitoring</span>
        </div>
        <div className="text-gray-400 text-sm font-mono">00:00</div>
      </header>
      
      {/* Main content */}
      <main className="flex flex-1 overflow-hidden">
        {/* Left Sidebar */}
        <aside className="w-72 border-r border-[#2a2a2a] p-4 flex flex-col gap-4 bg-[#0d0d0d] overflow-y-auto">
          <div className="h-32 border border-[#2a2a2a] rounded-lg bg-[#161616] p-4 text-gray-500 text-sm">StatsBar placeholder</div>
          <div className="flex-1 border border-[#2a2a2a] rounded-lg bg-[#161616] p-4 text-gray-500 text-sm">AttackerProfile placeholder</div>
        </aside>
        
        {/* Center Panel */}
        <section className="flex-1 bg-[#0d0d0d] flex items-center justify-center border-r border-[#2a2a2a]">
          <div className="text-gray-500 text-sm">NetworkGraph placeholder</div>
        </section>
        
        {/* Right Sidebar */}
        <aside className="w-80 flex flex-col bg-[#0d0d0d]">
          <div className="flex-1 border-b border-[#2a2a2a] p-4 overflow-y-auto text-gray-500 text-sm">
            AlertFeed placeholder
          </div>
          <div className="h-64 p-4 text-gray-500 text-sm">
            MitreHeatmap placeholder
          </div>
        </aside>
      </main>
    </div>
  );
}

export default App;
