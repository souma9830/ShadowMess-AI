import React from 'react';
import { useShadowStore } from '../store/useShadowStore';
import { AlertCircle, Info, ShieldAlert, Bird } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function AlertFeed() {
  const alerts = useShadowStore(state => state.alerts);

  const getIcon = (severity) => {
    switch(severity) {
      case 'critical': return <ShieldAlert className="text-shadowRed w-4 h-4" />;
      case 'warning': return <AlertCircle className="text-shadowAmber w-4 h-4" />;
      case 'canary': return <Bird className="text-shadowPurple w-4 h-4" />;
      default: return <Info className="text-shadowGreen w-4 h-4" />;
    }
  };

  return (
    <div className="flex flex-col h-full p-4">
      <h3 className="text-xs font-bold text-gray-400 mb-3 uppercase tracking-wider shrink-0">Live Alerts</h3>
      <div className="flex-1 overflow-y-auto pr-1 space-y-2">
        {alerts.length === 0 ? (
          <div className="text-xs text-gray-500 italic">No alerts — system monitoring</div>
        ) : (
          <AnimatePresence initial={false}>
            {alerts.map(alert => (
              <motion.div
                key={alert.id}
                initial={{ opacity: 0, y: -12 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
                className="bg-[#1a1a1a] border border-[#2a2a2a] p-2 rounded flex items-start gap-2 font-mono"
              >
                <div className="mt-0.5 shrink-0">{getIcon(alert.severity)}</div>
                <div className="flex-1 min-w-0 leading-tight">
                  <div className="text-xs text-gray-300 break-words">
                    <span className="text-gray-500 mr-1">
                      [{new Date(alert.timestamp).toLocaleTimeString('en-US', { hour12: false })}]
                    </span>
                    <span className="text-gray-400 mr-1 font-bold">
                      [{alert.severity === 'critical' ? 'CRIT' : alert.severity === 'warning' ? 'WARN' : alert.severity === 'canary' ? 'CNRY' : 'INFO'}]
                    </span>
                    {alert.message}
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}
