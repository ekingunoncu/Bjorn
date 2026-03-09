const BASE = '';

async function get<T>(url: string): Promise<T> {
  const res = await fetch(BASE + url);
  if (!res.ok) throw new Error(`GET ${url}: ${res.status}`);
  return res.json();
}

async function getText(url: string): Promise<string> {
  const res = await fetch(BASE + url);
  if (!res.ok) throw new Error(`GET ${url}: ${res.status}`);
  return res.text();
}

async function post<T>(url: string, body?: unknown): Promise<T> {
  const res = await fetch(BASE + url, {
    method: 'POST',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`POST ${url}: ${res.status}`);
  return res.json();
}

export interface BjornStatus {
  bjorn_status: string;
  status_text: string;
  alive_hosts: number;
  total_hosts: number;
  targets: number;
  open_ports: number;
  vulnerabilities: number;
  credentials: number;
  stolen_data: number;
  zombies: number;
  level: number;
  coins: number;
}

export interface ToolCallEntry {
  timestamp: string;
  tool: string;
  args: Record<string, unknown>;
  result_preview: string;
  success: boolean;
}

export interface NetKBRow {
  IPs: string;
  'MAC Address': string;
  Hostnames: string;
  Alive: string;
  Ports: string;
  [key: string]: string;
}

export interface NetKBJson {
  ips: string[];
  ports: Record<string, string[]>;
  actions: string[];
}

export interface LootFile {
  name: string;
  is_directory: boolean;
  path?: string;
  children?: LootFile[];
}

export interface ConfigData {
  [key: string]: string | number | boolean | string[];
}

export interface WifiNetwork {
  networks: string[];
  current_ssid: string;
}

export const api = {
  getStatus: () => get<BjornStatus>('/api/status'),
  getToolLog: () => get<ToolCallEntry[]>('/tool_log'),
  getConfig: () => get<ConfigData>('/load_config'),
  saveConfig: (data: ConfigData) => post<{status: string}>('/save_config', data),
  restoreDefaultConfig: () => get<ConfigData>('/restore_default_config'),
  getNetkbJson: () => get<NetKBJson>('/netkb_data_json'),
  getNetkbHtml: () => getText('/netkb_data'),
  getNetworkHtml: () => getText('/network_data'),
  getCredentialsHtml: () => getText('/list_credentials'),
  getLoot: () => get<LootFile[]>('/list_files'),
  getLogs: () => getText('/get_logs'),
  scanWifi: () => get<WifiNetwork>('/scan_wifi'),
  connectWifi: (ssid: string, password: string) =>
    post<{status: string}>('/connect_wifi', { ssid, password }),
  disconnectWifi: () => post<{status: string}>('/disconnect_wifi'),
  startOrchestrator: () => post<{status: string}>('/start_orchestrator'),
  stopOrchestrator: () => post<{status: string}>('/stop_orchestrator'),
  reboot: () => post<{status: string}>('/reboot'),
  shutdown: () => post<{status: string}>('/shutdown'),
  restartService: () => post<{status: string}>('/restart_bjorn_service'),
  clearFiles: () => post<{status: string}>('/clear_files'),
  clearFilesLight: () => post<{status: string}>('/clear_files_light'),
  initializeCsv: () => post<{status: string}>('/initialize_csv'),
  backup: () => post<{status: string; url?: string; filename?: string}>('/backup'),
  executeAttack: (ip: string, port: string, action: string) =>
    post<{status: string}>('/execute_manual_attack', { ip, port, action }),
};
