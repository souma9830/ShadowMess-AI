import React from 'react';
import { useShadowStore } from '../store/useShadowStore';
import { motion } from 'framer-motion';

const INTEREST_LABELS = [
  { key: 'credentials', label: 'Credentials',    color: '#E24B4A' },
  { key: 'ad_admin',    label: 'AD / Admins',     color: '#7F77DD' },
  { key: 'cloud',       label: 'Cloud Assets',    color: '#378ADD' },
  { key: 'finance',     label: 'Finance Data',    color: '#EF9F27' },
  { key: 'lateral',     label: 'Lateral Move',    color: '#D4537E' },
];

export default function AttackerInterests() {
  const interests = useShadowStore(state => state.attackerInterests);

  const max = Math.max(1, ...Object.values(interests));
  const total = Object.values(interests).reduce((a, b) => a + b, 0);

  return (
    <div className="flex flex-col h-full bg-[#111] overflow-hidden border-t border-[#2a2a2a]">
      <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider px-4 pt-3 pb-2 flex justify-between items-center">
        <span>Attacker Interests</span>
        <span className="text-[9px] bg-[#2a2a2a] px-1.5 py-0.5 rounded text-gray-500">
          {total} signals
        </span>
      </h3>

      <div className="flex-1 overflow-y-auto px-4 pb-4 flex flex-col gap-3">
        {total === 0 ? (
          <div className="text-xs text-gray-600 text-center py-6">
            Waiting for attacker activity...
          </div>
        ) : (
          INTEREST_LABELS.map(({ key, label, color }) => {
            const count = interests[key] || 0;
            const pct = Math.round((count / max) * 100);
            return (
              <div key={key}>
                <div className="flex justify-between text-[10px] mb-1">
                  <span className="text-gray-300 font-mono">{label}</span>
                  <span className="text-gray-500">{count}</span>
                </div>
                <div className="h-2 w-full bg-[#2a2a2a] rounded-full overflow-hidden">
                  <motion.div
                    className="h-full rounded-full"
                    style={{ backgroundColor: color }}
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.6, ease: 'easeOut' }}
                  />
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
