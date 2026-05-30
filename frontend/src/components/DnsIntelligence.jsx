import React from 'react';
import { useShadowStore } from '../store/useShadowStore';
import { motion, AnimatePresence } from 'framer-motion';

export default function DnsIntelligence() {
  const dnsQueries = useShadowStore(state => state.dnsQueries);

  return (
    <div className="flex flex-col h-full bg-[#111] overflow-hidden border-t border-[#2a2a2a]">
      <h3 className="text-xs font-bold text-gray-400 mb-2 uppercase tracking-wider px-4 pt-3 flex justify-between items-center">
        <span>DNS Intelligence</span>
        <span className="text-[9px] bg-[#2a2a2a] px-1.5 py-0.5 rounded text-gray-500">
          Last {dnsQueries.length}
        </span>
      </h3>
      <div className="flex-1 overflow-y-auto px-4 pb-4 space-y-1">
        {dnsQueries.length === 0 ? (
          <div className="text-xs text-gray-600 text-center py-4">Waiting for DNS traffic...</div>
        ) : (
          <AnimatePresence initial={false}>
            {dnsQueries.map((q, i) => {
              const isPlanted = q.is_planted;
              return (
                <motion.div 
                  key={q.timestamp + i}
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className={`text-[10px] p-2 rounded border flex flex-col gap-1 ${
                    isPlanted 
                      ? 'bg-shadowAmber/10 border-shadowAmber text-shadowAmber' 
                      : 'bg-[#1a1a1a] border-[#333] text-gray-400'
                  }`}
                >
                  <div className="flex justify-between items-start">
                    <span className="font-mono font-bold truncate max-w-[140px]" title={q.hostname}>
                      {q.hostname}
                    </span>
                    <span className="opacity-60 text-[9px]">
                      {new Date(q.timestamp * 1000).toLocaleTimeString([], { hour12: false })}
                    </span>
                  </div>
                  <div className="flex justify-between items-end">
                    <span className="font-mono opacity-80">{q.resolved_to}</span>
                    <span className="opacity-50 text-[9px]">{q.source_ip}</span>
                  </div>
                  {isPlanted && (
                    <div className="mt-1 pt-1 border-t border-shadowAmber/30 text-[9px] font-bold text-white flex items-center gap-1">
                      <span>🐦</span> {q.canary_hint}
                    </div>
                  )}
                </motion.div>
              );
            })}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}
