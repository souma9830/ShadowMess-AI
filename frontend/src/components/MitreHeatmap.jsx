import React from 'react';
import { useShadowStore } from '../store/useShadowStore';
import { motion } from 'framer-motion';

export default function MitreHeatmap() {
  const mitreTechniques = useShadowStore(state => state.mitreTechniques);
  
  const techniquesList = Object.entries(mitreTechniques).map(([id, data]) => ({
    id,
    ...data
  })).sort((a, b) => b.count - a.count);

  return (
    <div className="flex flex-col h-full bg-[#111] overflow-hidden">
      <h3 className="text-xs font-bold text-gray-400 mb-2 uppercase tracking-wider px-4 pt-3 flex justify-between items-center">
        <span>MITRE ATT&CK Matrix</span>
        <span className="text-[9px] bg-[#2a2a2a] px-1.5 py-0.5 rounded text-gray-500">
          {techniquesList.length} Observed
        </span>
      </h3>
      <div className="flex-1 overflow-y-auto px-4 pb-4">
        {techniquesList.length === 0 ? (
          <div className="text-xs text-gray-600 text-center h-full flex items-center justify-center">
            No techniques mapped yet
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-2">
            {techniquesList.map((tech) => {
              // Higher count = more intense red
              const opacity = Math.min(0.2 + (tech.count * 0.1), 0.8);
              
              return (
                <motion.div
                  key={tech.id}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="flex flex-col p-2 border border-shadowRed/30 rounded text-[9px] relative overflow-hidden group"
                  title={`${tech.tactic} - ${tech.count} occurrences`}
                >
                  <div 
                    className="absolute inset-0 bg-shadowRed transition-opacity duration-500" 
                    style={{ opacity }}
                  />
                  <div className="relative z-10 flex justify-between mb-1 text-gray-400 group-hover:text-white transition-colors">
                    <span className="font-mono font-bold">{tech.id}</span>
                    <span className="font-bold">x{tech.count}</span>
                  </div>
                  <div className="relative z-10 text-white font-bold leading-tight truncate">
                    {tech.name}
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
