import React from 'react';
import { useShadowStore } from '../store/useShadowStore';
import { useShallow } from 'zustand/react/shallow';
import { motion } from 'framer-motion';

export default function AttackerProfile() {
  const { focusedAttackerIp, attackerProfiles, threatScores } = useShadowStore(
    useShallow(state => ({
      focusedAttackerIp: state.focusedAttackerIp,
      attackerProfiles: state.attackerProfiles,
      threatScores: state.threatScores,
    }))
  );
  const profile = focusedAttackerIp ? attackerProfiles[focusedAttackerIp] : null;
  const threatScore = focusedAttackerIp ? threatScores[focusedAttackerIp] : null;

  if (!focusedAttackerIp) {
    return (
      <div className="w-full h-full flex items-center justify-center text-gray-500 text-sm">
        Select an attacker to view profile
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="w-full h-full flex flex-col items-center justify-center text-gray-400 text-sm gap-3">
        <div className="w-6 h-6 border-2 border-shadowPurple border-t-transparent rounded-full animate-spin"></div>
        Behavioral analysis pending...
      </div>
    );
  }

  const getSkillColor = (skill) => {
    switch(skill?.toLowerCase()) {
      case 'script kiddie': return 'text-shadowGreen border-shadowGreen bg-shadowGreen/10';
      case 'intermediate': return 'text-shadowAmber border-shadowAmber bg-shadowAmber/10';
      case 'advanced': return 'text-orange-500 border-orange-500 bg-orange-500/10';
      case 'nation-state apt': return 'text-shadowRed border-shadowRed bg-shadowRed/10 animate-pulse shadow-[0_0_8px_rgba(226,75,74,0.5)]';
      default: return 'text-gray-400 border-gray-600 bg-gray-800';
    }
  };

  return (
    <motion.div 
      key={focusedAttackerIp + profile.skill_level}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="flex flex-col h-full text-sm"
    >
      <h3 className="text-xs font-bold text-gray-400 mb-3 uppercase tracking-wider px-4 pt-4">Attacker Profile</h3>
      <div className="px-4 flex flex-col gap-4 overflow-y-auto pb-4">
        <div className="flex justify-between items-start">
          <div className="font-mono text-lg font-bold text-white">{focusedAttackerIp}</div>
          <div className={`px-2 py-1 text-[10px] font-bold uppercase border rounded ${getSkillColor(profile.skill_level)}`}>
            {profile.skill_level || 'Unknown'}
          </div>
        </div>
        
        {profile.apt_resemblance && (
          <div>
            <div className="text-[10px] text-gray-500 uppercase mb-1">APT Resemblance</div>
            <div className="inline-block bg-shadowPurple/20 text-shadowPurple border border-shadowPurple/30 px-2 py-0.5 rounded text-xs font-mono">
              {profile.apt_resemblance}
            </div>
          </div>
        )}

        {/* Threat Score (ML Anomaly) */}
        {threatScore && (
          <div>
            <div className="text-[10px] text-gray-500 uppercase mb-1 flex justify-between">
              <span>ML Anomaly Score</span>
              <span className="flex items-center gap-2">
                {threatScore.isAnomalous && <span className="text-[9px] bg-shadowRed text-white px-1 rounded">ANOMALOUS</span>}
                {Math.round(threatScore.score * 100)}%
              </span>
            </div>
            <div className="h-1 w-full bg-[#2a2a2a] rounded-full overflow-hidden">
              <div 
                className={`h-full transition-all duration-700 ease-out ${threatScore.isAnomalous ? 'bg-shadowRed' : 'bg-gradient-to-r from-shadowGreen to-shadowAmber'}`}
                style={{ width: `${Math.min(100, threatScore.score * 100)}%` }}
              />
            </div>
          </div>
        )}

        <div>
          <div className="text-[10px] text-gray-500 uppercase mb-1 flex justify-between">
            <span>Confidence</span>
            <span>{Math.round((profile.confidence || 0) * 100)}%</span>
          </div>
          <div className="h-1 w-full bg-[#2a2a2a] rounded-full overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-shadowRed to-shadowGreen" 
              style={{ width: `${(profile.confidence || 0) * 100}%` }}
            ></div>
          </div>
        </div>

        <div>
          <div className="text-[10px] text-gray-500 uppercase mb-1">Objective</div>
          <div className="text-gray-200 italic">{profile.objective || 'Unknown'}</div>
        </div>

        {profile.tools_detected && profile.tools_detected.length > 0 && (
          <div>
            <div className="text-[10px] text-gray-500 uppercase mb-2">Tools Detected</div>
            <div className="flex flex-wrap gap-2">
              {profile.tools_detected.map(tool => (
                <span key={tool} className="bg-[#1a1a1a] border border-[#333] text-gray-300 font-mono text-[10px] px-2 py-1 rounded">
                  {tool}
                </span>
              ))}
            </div>
          </div>
        )}

        {profile.summary && (
          <div>
            <div className="text-[10px] text-gray-500 uppercase mb-1">Summary</div>
            <div className="text-gray-300 text-xs leading-relaxed">{profile.summary}</div>
          </div>
        )}

        {/* Intelligence Export Buttons */}
        <div className="mt-4 flex gap-2">
          <button
            onClick={() => window.open(`/api/export/stix/${focusedAttackerIp}`)}
            title="Download STIX 2.1 Threat Intel Bundle"
            className="flex-1 bg-[#1a1a1a] hover:bg-[#2a2a2a] border border-[#333] text-center text-[10px] text-gray-300 py-1.5 rounded uppercase tracking-wider transition-colors"
          >
            Export STIX 2.1
          </button>
          <button
            onClick={() => window.open(`/api/export/report/${focusedAttackerIp}`)}
            title="Download PDF Threat Report"
            className="flex-1 bg-[#1a1a1a] hover:bg-[#2a2a2a] border border-[#333] text-center text-[10px] text-gray-300 py-1.5 rounded uppercase tracking-wider transition-colors"
          >
            Generate Report
          </button>
        </div>
      </div>
    </motion.div>
  );
}
