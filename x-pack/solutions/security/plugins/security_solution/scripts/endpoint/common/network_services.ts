/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { networkInterfaces } from 'node:os';

const getInterfacePriority = (name: string): number => {
  if (/^(en|eth|wlan)\d*/.test(name)) {
    return 0;
  }

  if (/^(bridge|utun|llw|awdl|lo)\d*/.test(name)) {
    return 2;
  }

  return 1;
};

export const getLocalhostRealIp = (): string => {
  if (process.env.KIBANA_LOCALHOST_REAL_IP) {
    // #region agent log
    void fetch('http://127.0.0.1:7647/ingest/9df83130-3a51-44fa-8d29-9d2534c17d2e',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'3c19b8'},body:JSON.stringify({sessionId:'3c19b8',runId:'initial',hypothesisId:'H1,H2',location:'common/network_services.ts:getLocalhostRealIp',message:'Using configured localhost real IP override',data:{source:'env',localhostRealIp:process.env.KIBANA_LOCALHOST_REAL_IP},timestamp:Date.now()})}).catch(()=>{});
    // #endregion
    return process.env.KIBANA_LOCALHOST_REAL_IP;
  }
  const interfaces = Object.entries(networkInterfaces());
  const candidates = interfaces.flatMap(([name, netInterfaceList]) =>
    (netInterfaceList ?? []).map((networkInterface) => ({
      name,
      address: networkInterface.address,
      family: networkInterface.family,
      internal: networkInterface.internal,
      priority: getInterfacePriority(name),
      eligible:
        networkInterface.family === 'IPv4' &&
        networkInterface.internal === false &&
        Boolean(networkInterface.address) &&
        !networkInterface.address.startsWith('169.254.') &&
        !networkInterface.address.endsWith('.0'),
    }))
  );

  const selected = candidates
    .filter((candidate) => candidate.eligible)
    .sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name))[0];

  if (selected) {
    // #region agent log
    void fetch('http://127.0.0.1:7647/ingest/9df83130-3a51-44fa-8d29-9d2534c17d2e',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'3c19b8'},body:JSON.stringify({sessionId:'3c19b8',runId:'initial',hypothesisId:'H1,H2',location:'common/network_services.ts:getLocalhostRealIp',message:'Selected localhost real IP from prioritized network interfaces',data:{source:'networkInterfaces',selectedInterface:selected.name,selectedAddress:selected.address,selectedPriority:selected.priority,candidates},timestamp:Date.now()})}).catch(()=>{});
    // #endregion
    return selected.address;
  }

  // #region agent log
  void fetch('http://127.0.0.1:7647/ingest/9df83130-3a51-44fa-8d29-9d2534c17d2e',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'3c19b8'},body:JSON.stringify({sessionId:'3c19b8',runId:'initial',hypothesisId:'H1,H2',location:'common/network_services.ts:getLocalhostRealIp',message:'Falling back because no eligible localhost real IP was found',data:{source:'fallback',localhostRealIp:'0.0.0.0',candidates},timestamp:Date.now()})}).catch(()=>{});
  // #endregion
  return '0.0.0.0';
};
