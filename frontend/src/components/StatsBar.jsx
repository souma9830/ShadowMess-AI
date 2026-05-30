import React from 'react';
import { useShadowStore } from '../store/useShadowStore';
import { Activity, Clock, Terminal, ShieldAlert } from 'lucide-react';

function formatDwellTime(totalSeconds) {
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

export default function StatsBar() {
  const { sessionStats, isDeceptionActive } = useShadowStore();

  if (!isDeceptionActive) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        Waiting for threat...
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-2 h-full p-2">
      <div className="bg-[#1a1a1a] p-2 rounded flex items-center gap-3 border border-[#2a2a2a]">
        <Clock className="text-shadowPurple w-5 h-5" />
        <div>
          <div className="text-[10px] text-gray-400 uppercase tracking-wider">Dwell Time</div>
          <div className="text-lg font-mono leading-none">{formatDwellTime(sessionStats.dwellTimeSeconds)}</div>
        </div>
      </div>
      <div className="bg-[#1a1a1a] p-2 rounded flex items-center gap-3 border border-[#2a2a2a]">
        <Activity className="text-shadowGreen w-5 h-5" />
        <div>
          <div className="text-[10px] text-gray-400 uppercase tracking-wider">Explored</div>
          <div className="text-lg font-mono leading-none">{sessionStats.nodesExplored}</div>
        </div>
      </div>
      <div className="bg-[#1a1a1a] p-2 rounded flex items-center gap-3 border border-[#2a2a2a]">
        <ShieldAlert className="text-shadowAmber w-5 h-5" />
        <div>
          <div className="text-[10px] text-gray-400 uppercase tracking-wider">Logins</div>
          <div className="text-lg font-mono leading-none">{sessionStats.loginAttempts}</div>
        </div>
      </div>
      <div className="bg-[#1a1a1a] p-2 rounded flex items-center gap-3 border border-[#2a2a2a]">
        <Terminal className="text-shadowRed w-5 h-5" />
        <div>
          <div className="text-[10px] text-gray-400 uppercase tracking-wider">Commands</div>
          <div className="text-lg font-mono leading-none">{sessionStats.commandsRun}</div>
        </div>
      </div>
    </div>
  );
}
