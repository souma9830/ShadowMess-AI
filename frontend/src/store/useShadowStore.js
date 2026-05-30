import { create } from 'zustand';

export const useShadowStore = create((set, get) => ({
  isDeceptionActive: false,
  attackerIp: null,
  topologyGeneration: 0,
  nodes: [],
  edges: [],
  actions: [],
  alerts: [],
  attackerProfiles: {},
  focusedAttackerIp: null,
  activeSessions: [],
  nodeHits: {},
  mitreTechniques: {},
  sessionStats: {
    dwellTimeSeconds: 0,
    nodesExplored: 0,
    loginAttempts: 0,
    commandsRun: 0,
  },
  isMutating: false,
  canaryTokens: [],
  stolenCredentials: [],
  threatScores: {},
  dnsQueries: [],
  activeBreadcrumbs: 0,

  activateDeception: (attackerIp) => set({ isDeceptionActive: true, attackerIp }),
  
  updateTopology: (nodes, edges, generation) => set({ nodes, edges, topologyGeneration: generation }),
  
  addAction: (action) => set((state) => {
    const session = state.activeSessions.find(s => s.ip === action.attacker_ip) || { ip: action.attacker_ip, action_count: 0, first_seen: action.timestamp, last_seen: action.timestamp };
    const updatedSessions = state.activeSessions.filter(s => s.ip !== action.attacker_ip);
    updatedSessions.push({
      ...session,
      action_count: (session.action_count || 0) + 1,
      last_seen: action.timestamp
    });

    return { 
      actions: [action, ...state.actions].slice(0, 50),
      nodeHits: { ...state.nodeHits, [action.target_node_id]: action.attacker_ip },
      activeSessions: updatedSessions
    };
  }),
  
  addAlert: (message, severity) => set((state) => ({
    alerts: [{ id: Date.now().toString() + Math.random(), message, severity, timestamp: Date.now() }, ...state.alerts].slice(0, 20)
  })),
  
  setFocusedAttacker: (ip) => set({ focusedAttackerIp: ip }),
  
  updateSession: (ip, stats) => set((state) => {
    const exists = state.activeSessions.find(s => s.ip === ip);
    if (exists) {
      return { activeSessions: state.activeSessions.map(s => s.ip === ip ? { ...s, ...stats } : s) };
    }
    return { activeSessions: [...state.activeSessions, { ip, ...stats }] };
  }),
  
  setAttackerProfiles: (profiles) => set({ attackerProfiles: profiles }),
  
  tagMitreTechnique: (technique_id, name, tactic) => set((state) => {
    const newTechniques = { ...state.mitreTechniques };
    if (!newTechniques[technique_id]) {
      newTechniques[technique_id] = { name, count: 0, tactic };
    }
    newTechniques[technique_id].count += 1;
    return { mitreTechniques: newTechniques };
  }),
  
  incrementStat: (stat, by = 1) => set((state) => ({
    sessionStats: { ...state.sessionStats, [stat]: state.sessionStats[stat] + by }
  })),
  
  setMutating: (bool) => set({ isMutating: bool }),
  
  markCanaryTriggered: (token_id, triggered_by_ip) => set((state) => ({
    canaryTokens: state.canaryTokens.map(t => 
      t.token_id === token_id ? { ...t, triggered: true, triggered_at: Date.now(), triggered_by_ip } : t
    )
  })),
  
  markCredentialStolen: (cred_id, accessed_at) => set((state) => ({
    stolenCredentials: state.stolenCredentials.map(c => 
      c.cred_id === cred_id ? { ...c, accessed: true, accessed_at } : c
    )
  })),
  
  setThreatScore: (ip, score, isAnomalous) => set((state) => ({
    threatScores: { ...state.threatScores, [ip]: { score, isAnomalous } }
  })),
  
  addDnsQuery: (query) => set((state) => ({
    dnsQueries: [query, ...state.dnsQueries].slice(0, 10)
  })),
  
  setBreadcrumbs: (count) => set({ activeBreadcrumbs: count }),
  
  reset: () => set({
    isDeceptionActive: false, attackerIp: null, topologyGeneration: 0,
    nodes: [], edges: [], actions: [], alerts: [], 
    attackerProfiles: {}, focusedAttackerIp: null, activeSessions: [], nodeHits: {},
    mitreTechniques: {}, sessionStats: { dwellTimeSeconds: 0, nodesExplored: 0, loginAttempts: 0, commandsRun: 0 },
    isMutating: false, canaryTokens: [], stolenCredentials: [],
    threatScores: {}, dnsQueries: [], activeBreadcrumbs: 0
  })
}));
