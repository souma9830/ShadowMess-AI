import React from 'react';
import socket from '../services/socket';
import { EVENTS } from '../services/events';

export default function DemoControlBar() {
  // Only show in development mode
  if (!import.meta.env.DEV) return null;

  return (
    <div className="absolute bottom-6 left-1/2 -translate-x-1/2 bg-[#1a1a1a]/90 backdrop-blur border border-[#333] rounded-xl p-2 flex gap-3 z-50 shadow-2xl shadow-black">
      <button 
        onClick={() => socket.emit(EVENTS.TRIGGER_SCAN)}
        className="bg-[#2a2a2a] border border-[#444] text-white text-sm px-4 py-2 rounded-lg hover:border-shadowRed hover:text-shadowRed transition-colors"
      >
        ⚡ Trigger Scan
      </button>
      <button 
        onClick={() => socket.emit(EVENTS.TRIGGER_LOGIN)}
        className="bg-[#2a2a2a] border border-[#444] text-white text-sm px-4 py-2 rounded-lg hover:border-shadowAmber hover:text-shadowAmber transition-colors"
      >
        🔑 Simulate Login
      </button>
      <button 
        onClick={() => socket.emit(EVENTS.TRIGGER_MUTATE)}
        className="bg-[#2a2a2a] border border-[#444] text-white text-sm px-4 py-2 rounded-lg hover:border-shadowPurple hover:text-shadowPurple transition-colors"
      >
        🌫 Trigger Mutation
      </button>
    </div>
  );
}
