import { useEffect, useState } from 'react';
import socket from '../services/socket';
import { useShadowStore } from '../store/useShadowStore';
import { EVENTS } from '../services/events';

export function useSocketEvents() {
  const [isConnected, setIsConnected] = useState(socket.connected);

  useEffect(() => {
    function onConnect() { setIsConnected(true); }
    function onDisconnect() { setIsConnected(false); }

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);

    socket.on(EVENTS.RECON_DETECTED, (data) => {
      const store = useShadowStore.getState();
      store.activateDeception(data.source_ip);
      store.setFocusedAttacker(data.source_ip);
      store.addAlert(`Recon detected from ${data.source_ip}`, 'critical');
    });

    socket.on(EVENTS.TOPOLOGY_UPDATE, (data) => {
      useShadowStore.getState().updateTopology(data.nodes, data.edges, data.generation);
    });

    socket.on(EVENTS.TOPOLOGY_MUTATING, () => {
      useShadowStore.getState().setMutating(true);
      setTimeout(() => useShadowStore.getState().setMutating(false), 2200);
    });

    socket.on(EVENTS.ATTACKER_ACTION, (data) => {
      const store = useShadowStore.getState();
      // Check BEFORE addAction so we read the pre-mutation state
      const alreadyExplored = store.actions.some(a => a.target_node_id === data.target_node_id);
      store.addAction(data);
      if (data.action_type === 'login_attempt') store.incrementStat('loginAttempts');
      if (data.action_type === 'command_exec') store.incrementStat('commandsRun');
      if (!alreadyExplored) store.incrementStat('nodesExplored');
    });

    socket.on(EVENTS.PROFILE_UPDATE, (data) => {
      const store = useShadowStore.getState();
      const profiles = { ...store.attackerProfiles, [data.attacker_ip]: data };
      store.setAttackerProfiles(profiles);
      store.updateSession(data.attacker_ip, { skill_level: data.skill_level });
    });

    socket.on(EVENTS.MITRE_TAG, (data) => {
      useShadowStore.getState().tagMitreTechnique(data.technique_id, data.technique_name, data.tactic);
    });

    socket.on(EVENTS.ALERT, (data) => {
      useShadowStore.getState().addAlert(data.message, data.severity);
    });

    socket.on(EVENTS.CONTAINER_SPAWNED, (data) => {
      useShadowStore.getState().addAlert(`Container spawned: ${data.node_type}`, 'info');
    });

    socket.on(EVENTS.CANARY_TRIGGERED, (data) => {
      useShadowStore.getState().markCanaryTriggered(data.token_id, data.triggered_by_ip);
      useShadowStore.getState().addAlert(`🐦 Canary triggered: ${data.label}`, 'canary');
    });

    socket.on(EVENTS.CREDENTIAL_STOLEN, (data) => {
      useShadowStore.getState().markCredentialStolen(data.cred_id, data.accessed_at);
      useShadowStore.getState().addAlert(`Fake credential accessed: ${data.filename}`, 'warning');
    });

    socket.on(EVENTS.LURE_SPAWNED, (data) => {
      useShadowStore.getState().addAlert(`Adaptive lure deployed: ${data.label}`, 'info');
    });

    socket.on(EVENTS.THREAT_SCORE, (data) => {
      useShadowStore.getState().setThreatScore(data.attacker_ip, data.threat_score, data.is_anomalous);
    });

    socket.on(EVENTS.DNS_QUERY, (data) => {
      useShadowStore.getState().addDnsQuery(data);
    });

    socket.on(EVENTS.BREADCRUMB_UPDATE, (data) => {
      useShadowStore.getState().setBreadcrumbs(data.active_count);
    });

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off(EVENTS.RECON_DETECTED);
      socket.off(EVENTS.TOPOLOGY_UPDATE);
      socket.off(EVENTS.TOPOLOGY_MUTATING);
      socket.off(EVENTS.ATTACKER_ACTION);
      socket.off(EVENTS.PROFILE_UPDATE);
      socket.off(EVENTS.MITRE_TAG);
      socket.off(EVENTS.ALERT);
      socket.off(EVENTS.CONTAINER_SPAWNED);
      socket.off(EVENTS.CANARY_TRIGGERED);
      socket.off(EVENTS.CREDENTIAL_STOLEN);
      socket.off(EVENTS.LURE_SPAWNED);
      socket.off(EVENTS.THREAT_SCORE);
      socket.off(EVENTS.DNS_QUERY);
      socket.off(EVENTS.BREADCRUMB_UPDATE);
    };
  }, []);

  return { isConnected };
}
