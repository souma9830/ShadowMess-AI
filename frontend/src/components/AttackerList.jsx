import React from 'react';
import { useShadowStore } from '../store/useShadowStore';
import { useShallow } from 'zustand/react/shallow';

export default function AttackerList() {
  const { activeSessions, focusedAttackerIp, setFocusedAttacker } = useShadowStore(
    useShallow(state => ({
      activeSessions: state.activeSessions,
      focusedAttackerIp: state.focusedAttackerIp,
      setFocusedAttacker: state.setFocusedAttacker,
    }))
  );

  const getSkillColor = (skill) => {
    switch(skill?.toLowerCase()) {
      case 'script kiddie': return 'text-shadowGreen border-shadowGreen bg-shadowGreen/10';
      case 'intermediate': return 'text-shadowAmber border-shadowAmber bg-shadowAmber/10';
      case 'advanced': return 'text-orange-500 border-orange-500 bg-orange-500/10';
      case 'nation-state apt': return 'text-shadowRed border-shadowRed bg-shadowRed/10 animate-pulse';
      default: return 'text-gray-400 border-gray-600 bg-gray-800';
    }
  };

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <h3 className="text-xs font-bold text-gray-400 mb-3 uppercase tracking-wider px-4 pt-4">Active Threats</h3>
      <div className="flex-1 overflow-y-auto px-2 space-y-2 pb-2">
        {activeSessions.length === 0 ? (
          <div className="text-xs text-gray-500 px-2">No active threats.</div>
        ) : (
          activeSessions.map(session => {
            // last_seen is epoch seconds. Use Date.now()/1000 as fallback for demo triggers (timestamp=0)
            const lastSeenMs = (session.last_seen > 0 ? session.last_seen : Date.now() / 1000) * 1000;
            const isActive = (Date.now() - lastSeenMs) < 60000;
            const isFocused = focusedAttackerIp === session.ip;
            
            return (
              <div 
                key={session.ip}
                onClick={() => setFocusedAttacker(session.ip)}
                className={`cursor-pointer bg-[#1a1a1a] border p-3 rounded-lg transition-colors ${
                  isFocused ? 'border-shadowGreen shadow-[0_0_10px_rgba(29,158,117,0.2)]' : 'border-[#2a2a2a] hover:border-[#444]'
                }`}
              >
                <div className="flex justify-between items-center mb-2">
                  <span className="font-mono text-sm font-bold text-white">{session.ip}</span>
                  <div className="flex items-center gap-1.5">
                    <div className={`w-2 h-2 rounded-full ${isActive ? 'bg-shadowGreen' : 'bg-gray-600'}`}></div>
                    <span className="text-[10px] text-gray-400">{isActive ? 'Active' : 'Idle'}</span>
                  </div>
                </div>
                <div className="flex items-center justify-between mt-2">
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${getSkillColor(session.skill_level)}`}>
                    {session.skill_level || 'Unknown'}
                  </span>
                  <span className="text-[10px] text-gray-400">{session.action_count || 0} actions</span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
