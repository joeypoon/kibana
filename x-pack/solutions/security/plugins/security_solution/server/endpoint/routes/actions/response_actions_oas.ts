/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

type OasExamples = Record<string, { summary?: string; description?: string; value: unknown }>;

const responseActionOas =
  (
    operationId: string,
    examples: { request?: OasExamples; response?: OasExamples } = {},
    requestContentType: string = 'application/json'
  ) =>
  () => ({
    operationId,
    ...(examples.request
      ? { requestBody: { content: { [requestContentType]: { examples: examples.request } } } }
      : {}),
    ...(examples.response
      ? { responses: { 200: { content: { 'application/json': { examples: examples.response } } } } }
      : {}),
  });

export const scanActionOas = responseActionOas('EndpointScanAction', {
  request: {
    scanFile: {
      summary: 'Scan a file on an endpoint',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        parameters: { path: '/usr/my-file.txt' },
        comment: 'Scan the file for malware',
      },
    },
  },
  response: {
    ScanSuccess: {
      summary: 'Scan action successfully created',
      value: {
        data: {
          id: '27ba1b42-7cc6-4e53-86ce-675c876092b2',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          command: 'scan',
          agentType: 'endpoint',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2023-07-28T19:00:03.911Z',
          createdBy: 'elastic',
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          parameters: { path: '/usr/my-file.txt' },
          outputs: {},
        },
      },
    },
  },
});

export const isolateActionOas = responseActionOas('EndpointIsolateAction', {
  request: {
    single_endpoint: {
      summary:
        'Isolates a single host with an endpoint_id value of ed518850-681a-4d60-bb98-e22640cae2a8',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
      },
    },
    multiple_endpoints: {
      summary: 'Isolates several hosts; includes a comment',
      value: {
        endpoint_ids: [
          '9972d10e-4b9e-41aa-a534-a85e2a28ea42',
          'bc0e4f0c-3bca-4633-9fee-156c0b505d16',
          'fa89271b-b9d4-43f2-a684-307cffddeb5a',
        ],
        comment: 'Locked down, pending further investigation',
      },
    },
    with_case_id: {
      summary: 'Isolates a single host with a case_id value of 1234',
      value: {
        endpoint_ids: [
          '1aa1f8fd-0fb0-4fe4-8c30-92068272d3f0',
          'b30a11bf-1395-4707-b508-fbb45ef9793e',
        ],
        case_ids: ['4976be38-c134-4554-bd5e-0fd89ce63667'],
        comment: 'Isolating as initial response',
      },
    },
  },
  response: {
    IsolateSuccess: {
      summary: 'Isolate action successfully created',
      value: {
        action: '233db9ea-6733-4849-9226-5a7039c7161d',
        data: {
          id: '233db9ea-6733-4849-9226-5a7039c7161d',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          command: 'isolate',
          agentType: 'endpoint',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2022-07-29T19:08:49.126Z',
          createdBy: 'elastic',
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          outputs: {},
        },
      },
    },
  },
});

export const unisolateActionOas = responseActionOas('EndpointUnisolateAction', {
  request: {
    singleHost: {
      summary:
        'Releases a single host with an endpoint_id value of ed518850-681a-4d60-bb98-e22640cae2a8',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
      },
    },
    multipleHosts: {
      summary: 'Releases several hosts; includes a comment:',
      value: {
        endpoint_ids: [
          '9972d10e-4b9e-41aa-a534-a85e2a28ea42',
          'bc0e4f0c-3bca-4633-9fee-156c0b505d16',
          'fa89271b-b9d4-43f2-a684-307cffddeb5a',
        ],
        comment: 'Benign process identified, releasing group',
      },
    },
    withCaseId: {
      summary: 'Releases hosts with an associated case; includes a comment.',
      value: {
        endpoint_ids: [
          '1aa1f8fd-0fb0-4fe4-8c30-92068272d3f0',
          'b30a11bf-1395-4707-b508-fbb45ef9793e',
        ],
        case_ids: ['4976be38-c134-4554-bd5e-0fd89ce63667'],
        comment: 'Remediation complete, restoring network',
      },
    },
  },
  response: {
    UnisolateSuccess: {
      summary: 'Unisolate action successfully created',
      value: {
        action: '233db9ea-6733-4849-9226-5a7039c7161d',
        data: {
          id: '233db9ea-6733-4849-9226-5a7039c7161d',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          command: 'unisolate',
          agentType: 'endpoint',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2022-07-29T19:08:49.126Z',
          createdBy: 'elastic',
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          outputs: {},
        },
      },
    },
  },
});

export const killProcessActionOas = responseActionOas('EndpointKillProcessAction', {
  request: {
    byEntityId: {
      summary: 'Terminate a process by entity ID',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        parameters: { entity_id: 'abc123' },
        comment: 'Terminating malicious process',
      },
    },
    byPid: {
      summary: 'Terminate a process by PID',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        parameters: { pid: 1234 },
      },
    },
  },
  response: {
    KillProcessSuccess: {
      summary: 'Kill process action successfully created',
      value: {
        data: {
          id: '233db9ea-6733-4849-9226-5a7039c7161d',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          command: 'kill-process',
          agentType: 'endpoint',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2022-07-29T19:08:49.126Z',
          createdBy: 'elastic',
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          parameters: { entity_id: 'abc123' },
          outputs: {},
        },
      },
    },
  },
});

export const suspendProcessActionOas = responseActionOas('EndpointSuspendProcessAction', {
  request: {
    byEntityId: {
      summary: 'Suspend a process by entity ID',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        parameters: { entity_id: 'abc123' },
        comment: 'Suspending suspicious process',
      },
    },
    byPid: {
      summary: 'Suspend a process by PID',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        parameters: { pid: 1234 },
      },
    },
  },
  response: {
    SuspendProcessSuccess: {
      summary: 'Suspend process action successfully created',
      value: {
        data: {
          id: '233db9ea-6733-4849-9226-5a7039c7161d',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          command: 'suspend-process',
          agentType: 'endpoint',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2022-07-29T19:08:49.126Z',
          createdBy: 'elastic',
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          parameters: { entity_id: 'abc123' },
          outputs: {},
        },
      },
    },
  },
});

export const getProcessesActionOas = responseActionOas('EndpointGetProcessesAction', {
  request: {
    singleEndpoint: {
      summary: 'Get running processes on a single endpoint',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
      },
    },
  },
  response: {
    RunningProcsSuccess: {
      summary: 'Running processes action successfully created',
      value: {
        data: {
          id: '233db9ea-6733-4849-9226-5a7039c7161d',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          command: 'running-processes',
          agentType: 'endpoint',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2022-07-29T19:08:49.126Z',
          createdBy: 'elastic',
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          outputs: {},
        },
      },
    },
  },
});

export const getFileActionOas = responseActionOas('EndpointGetFileAction', {
  request: {
    getFile: {
      summary: 'Get a specific file from an endpoint',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        parameters: { path: '/usr/my-file.txt' },
        comment: 'Get my file',
      },
    },
  },
  response: {
    GetFileSuccess: {
      summary: 'Get file action successfully created',
      value: {
        data: {
          id: '27ba1b42-7cc6-4e53-86ce-675c876092b2',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          command: 'get-file',
          agentType: 'endpoint',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2023-07-28T19:00:03.911Z',
          createdBy: 'elastic',
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          parameters: { path: '/usr/my-file.txt' },
          outputs: {},
        },
      },
    },
  },
});

export const executeActionOas = responseActionOas('EndpointExecuteAction', {
  request: {
    executeCommand: {
      summary: 'Execute a shell command on an endpoint',
      value: {
        endpoint_ids: ['b3d6de74-36b0-4fa8-be46-c375bf1771bf'],
        parameters: { command: 'ls -al', timeout: 600 },
        comment: 'Get list of all files',
      },
    },
  },
  response: {
    ExecuteSuccess: {
      summary: 'Execute action successfully created',
      value: {
        data: {
          id: '9f934028-2300-4927-b531-b26376793dc4',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          command: 'execute',
          agentType: 'endpoint',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2023-07-28T18:43:27.362Z',
          createdBy: 'elastic',
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          parameters: { command: 'ls -al', timeout: 600 },
          outputs: {},
        },
      },
    },
  },
});

export const uploadActionOas = responseActionOas(
  'EndpointUploadAction',
  {
    request: {
      uploadFile: {
        summary: 'Upload a script file to a specific endpoint',
        value: {
          endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          comment: 'Pushing remediation script to host',
          parameters: { overwrite: false },
          file: 'RWxhc3RpYw==',
        },
      },
    },
    response: {
      UploadSuccess: {
        summary: 'Upload action successfully created',
        value: {
          data: {
            id: '9ff6aebc-2cb6-481e-8869-9b30036c9731',
            agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
            command: 'upload',
            agentType: 'endpoint',
            isExpired: false,
            isCompleted: false,
            wasSuccessful: false,
            status: 'pending',
            startedAt: '2023-07-03T15:07:22.837Z',
            createdBy: 'elastic',
            hosts: {
              'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'Host-5i6cuc8kdv' },
            },
            agentState: {
              'ed518850-681a-4d60-bb98-e22640cae2a8': {
                isCompleted: false,
                wasSuccessful: false,
              },
            },
            parameters: {
              file_name: 'fix-malware.sh',
              file_id: '10e4ce3d-4abb-4f93-a0cd-eaf63a489280',
              file_sha256: 'a0bed94220193ba4895c0aa5b4e7e293381d15765cb164ddf7be5cdd010ae42a',
              file_size: 69,
            },
            outputs: {},
          },
        },
      },
    },
  },
  'multipart/form-data'
);

export const runScriptActionOas = responseActionOas('RunScriptAction', {
  request: {
    'Elastic Defend': {
      summary: 'Run a script against an Elastic Defend agent',
      description: 'Endpoint runscript to collect logs',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        agent_type: 'endpoint',
        parameters: {
          scriptId: '1111-2222-3333-4444-5555-6666-7777-8888',
          scriptInput: '--path= /usr/log/exec.log',
        },
      },
    },
    SentinelOne: {
      summary: 'Run a script against a SentinelOne agent',
      description: 'SentinelOne runscript',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        agent_type: 'sentinel_one',
        parameters: {
          scriptId: '1111-2222-3333-4444-5555-6666-7777-8888',
          scriptInput: '--delete --paths-to-delete /tmp/temp_file.txt,/tmp/random_file.txt',
        },
      },
    },
    MDE: {
      summary: 'Run a script against a Microsoft Defender Endpoint agent',
      description: 'Microsoft Defender Endpoint runscript',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        agent_type: 'microsoft_defender_endpoint',
        parameters: {
          scriptName: 'my-script.ps1',
          args: '-param1 value1 -param2 value2',
        },
      },
    },
  },
  response: {
    RunScriptSuccess: {
      summary: 'Run script action successfully created',
      value: {
        data: {
          id: '233db9ea-6733-4849-9226-5a7039c7161d',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          command: 'runscript',
          agentType: 'sentinel_one',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2022-07-29T19:08:49.126Z',
          createdBy: 'elastic',
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          parameters: { scriptId: '1111-2222-3333-4444-5555-6666-7777-8888' },
          outputs: {},
        },
      },
    },
  },
});

export const cancelActionOas = responseActionOas('CancelAction', {
  request: {
    MicrosoftDefenderEndpoint: {
      summary: 'Cancel a response action on a Microsoft Defender for Endpoint host',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        agent_type: 'microsoft_defender_endpoint',
        parameters: { id: '7f8c9b2a-4d3e-4f5a-8b1c-2e3f4a5b6c7d' },
        comment: 'Cancelling action due to change in requirements',
      },
    },
  },
  response: {
    CancelSuccess: {
      summary: 'Cancel action successfully created',
      value: {
        data: {
          id: '233db9ea-6733-4849-9226-5a7039c7161d',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          command: 'cancel',
          agentType: 'microsoft_defender_endpoint',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2022-07-29T19:08:49.126Z',
          createdBy: 'elastic',
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          parameters: { id: '7f8c9b2a-4d3e-4f5a-8b1c-2e3f4a5b6c7d' },
          outputs: {},
        },
      },
    },
  },
});

export const memoryDumpActionOas = responseActionOas('EndpointGenerateMemoryDump', {
  request: {
    ProcessMemoryDump: {
      summary: 'Generate a memory dump from the host machine',
      value: {
        endpoint_ids: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
        agent_type: 'endpoint',
        parameters: { type: 'process', entity_id: 'abc123' },
        comment: 'Generating memory dump for investigation',
      },
    },
  },
  response: {
    MemoryDumpSuccessResponse: {
      summary: 'Memory dump action successfully created',
      value: {
        data: {
          id: '233db9ea-6733-4849-9226-5a7039c7161d',
          command: 'memory-dump',
          agentType: 'endpoint',
          isExpired: false,
          isCompleted: false,
          wasSuccessful: false,
          status: 'pending',
          startedAt: '2022-07-29T19:08:49.126Z',
          createdBy: 'elastic',
          agents: ['ed518850-681a-4d60-bb98-e22640cae2a8'],
          hosts: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': { name: 'gke-node-1235412' },
          },
          agentState: {
            'ed518850-681a-4d60-bb98-e22640cae2a8': {
              isCompleted: false,
              wasSuccessful: false,
            },
          },
          parameters: { type: 'process', entity_id: 'abc123' },
          outputs: {},
        },
      },
    },
  },
});
