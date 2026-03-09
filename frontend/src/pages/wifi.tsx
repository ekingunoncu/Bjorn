import { useState, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Separator } from '@/components/ui/separator'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { usePoll } from '@/hooks/use-poll'
import { api } from '@/lib/api'
import type { BjornStatus } from '@/lib/api'
import {
  Wifi, Radio, Zap, ShieldAlert, Key, Skull,
  FileSearch, Lock, Unlock, Eye, Ghost,
  RefreshCw, Play, Info,
} from 'lucide-react'

interface WifiFormState {
  bssid: string
  channel: string
  clientMac: string
  duration: string
  count: string
  timeout: string
  ssid: string
  captureFile: string
  wordlist: string
  pixieDust: boolean
}

const DEFAULT_FORM: WifiFormState = {
  bssid: '',
  channel: '',
  clientMac: '',
  duration: '30',
  count: '10',
  timeout: '120',
  ssid: '',
  captureFile: '',
  wordlist: '',
  pixieDust: true,
}

interface WifiTool {
  id: string
  name: string
  icon: typeof Wifi
  description: string
  helpText: string
  category: 'recon' | 'attack' | 'crack' | 'rogue' | 'report'
  fields: (keyof WifiFormState)[]
  action: (form: WifiFormState) => Promise<unknown>
}

const fetchStatus = () => api.getStatus()

const callWifiTool = async (tool: string, params: Record<string, unknown>) => {
  const res = await fetch('/api/wifi/' + tool, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  })
  // Fallback: call the MCP tool directly if the API doesn't exist
  if (res.status === 404) {
    return { info: `Tool ${tool} requires MCP client. Use Claude Code/Desktop to call wifi_${tool}.` }
  }
  return res.json()
}

const WIFI_TOOLS: WifiTool[] = [
  {
    id: 'analyze',
    name: 'Scan Networks',
    icon: Radio,
    description: 'Scan and analyze nearby WiFi networks',
    helpText: 'Uses airodump-ng to discover nearby access points, their encryption types, signal strength, connected clients, and WPS status. Set a specific BSSID to focus on one AP, or leave empty to scan all.',
    category: 'recon',
    fields: ['bssid', 'channel', 'duration'],
    action: (f) => callWifiTool('analyze', {
      target_bssid: f.bssid, channel: Number(f.channel) || 0, scan_duration: Number(f.duration),
    }),
  },
  {
    id: 'list_clients',
    name: 'List Clients',
    icon: Eye,
    description: 'List connected clients on a network',
    helpText: 'Captures client association frames to enumerate devices connected to a specific access point. Requires BSSID and channel of the target AP.',
    category: 'recon',
    fields: ['bssid', 'channel', 'duration'],
    action: (f) => callWifiTool('list_clients', {
      bssid: f.bssid, channel: Number(f.channel), duration: Number(f.duration),
    }),
  },
  {
    id: 'deauth',
    name: 'Deauth Attack',
    icon: Zap,
    description: 'Disconnect clients from a network',
    helpText: 'Sends IEEE 802.11 deauthentication frames to disconnect clients. If client MAC is empty, sends broadcast deauth to all clients. Count controls the number of packets sent.',
    category: 'attack',
    fields: ['bssid', 'channel', 'clientMac', 'count'],
    action: (f) => callWifiTool('deauth', {
      bssid: f.bssid, channel: Number(f.channel), client_mac: f.clientMac, count: Number(f.count),
    }),
  },
  {
    id: 'capture_handshake',
    name: 'Capture Handshake',
    icon: Key,
    description: 'Capture WPA/WPA2 4-way handshake',
    helpText: 'Captures the WPA/WPA2 4-way handshake by monitoring the target AP and optionally deauthing a client to trigger reconnection. The handshake can then be used for offline password cracking.',
    category: 'attack',
    fields: ['bssid', 'channel', 'clientMac', 'timeout'],
    action: (f) => callWifiTool('capture_handshake', {
      bssid: f.bssid, channel: Number(f.channel), client_mac: f.clientMac, timeout: Number(f.timeout),
    }),
  },
  {
    id: 'capture_pmkid',
    name: 'Capture PMKID',
    icon: FileSearch,
    description: 'Capture PMKID hash (clientless)',
    helpText: 'Captures PMKID from the AP without needing a connected client. This is a stealthier method than handshake capture. Uses hcxdumptool to extract the PMKID from the first EAPOL message.',
    category: 'attack',
    fields: ['bssid', 'channel', 'timeout'],
    action: (f) => callWifiTool('capture_pmkid', {
      bssid: f.bssid, channel: Number(f.channel), timeout: Number(f.timeout),
    }),
  },
  {
    id: 'crack_wpa',
    name: 'Crack WPA',
    icon: Unlock,
    description: 'Crack WPA with wordlist attack',
    helpText: 'Runs a dictionary/wordlist attack against a captured WPA handshake (.cap) or PMKID hash (.16800). Uses aircrack-ng for handshakes and hashcat for PMKID. Leave wordlist empty to use Bjorn\'s default passwords.txt.',
    category: 'crack',
    fields: ['captureFile', 'wordlist'],
    action: (f) => callWifiTool('crack_wpa', {
      capture_file: f.captureFile, wordlist: f.wordlist,
    }),
  },
  {
    id: 'crack_wps',
    name: 'Crack WPS',
    icon: Lock,
    description: 'Brute-force WPS PIN',
    helpText: 'Uses Reaver to brute-force the WPS PIN. Pixie Dust attack (enabled by default) exploits weak random number generation in WPS implementations for a much faster crack. Falls back to online brute force if Pixie Dust fails.',
    category: 'crack',
    fields: ['bssid', 'channel', 'timeout'],
    action: (f) => callWifiTool('crack_wps', {
      bssid: f.bssid, channel: Number(f.channel), timeout: Number(f.timeout), pixie_dust: f.pixieDust,
    }),
  },
  {
    id: 'crack_wep',
    name: 'Crack WEP',
    icon: ShieldAlert,
    description: 'Crack WEP encryption',
    helpText: 'Cracks WEP encryption using ARP replay injection to generate traffic, then uses aircrack-ng with the statistical (PTW) attack on captured IVs. WEP is fundamentally broken and can typically be cracked in minutes.',
    category: 'crack',
    fields: ['bssid', 'channel', 'timeout'],
    action: (f) => callWifiTool('crack_wep', {
      bssid: f.bssid, channel: Number(f.channel), timeout: Number(f.timeout),
    }),
  },
  {
    id: 'evil_twin',
    name: 'Evil Twin',
    icon: Skull,
    description: 'Fake AP with captive portal',
    helpText: 'Creates a rogue AP that clones a target network\'s SSID. Runs a captive portal that captures credentials when victims connect and try to access the internet. Uses hostapd + dnsmasq + iptables.',
    category: 'rogue',
    fields: ['ssid', 'channel', 'duration'],
    action: (f) => callWifiTool('evil_twin', {
      ssid: f.ssid, channel: Number(f.channel), duration: Number(f.duration),
    }),
  },
  {
    id: 'karma',
    name: 'KARMA Attack',
    icon: Ghost,
    description: 'Respond to all client probes',
    helpText: 'KARMA attack responds to all WiFi probe requests from nearby devices, tricking them into connecting to your rogue AP. Effective against devices looking for previously connected networks. Uses mdk4 beacon flood.',
    category: 'rogue',
    fields: ['duration'],
    action: (f) => callWifiTool('karma', {
      duration: Number(f.duration),
    }),
  },
  {
    id: 'get_handshakes',
    name: 'List Handshakes',
    icon: FileSearch,
    description: 'List captured handshake files',
    helpText: 'Shows all captured handshake (.cap) and PMKID (.16800) files stored on the device with metadata (file size, capture date).',
    category: 'report',
    fields: [],
    action: () => callWifiTool('get_handshakes', {}),
  },
  {
    id: 'get_cracked',
    name: 'Cracked Passwords',
    icon: Unlock,
    description: 'List all cracked WiFi passwords',
    helpText: 'Shows all WiFi passwords that have been successfully cracked, including BSSID, SSID, encryption type, password, cracking method, and timestamp.',
    category: 'report',
    fields: [],
    action: () => callWifiTool('get_cracked', {}),
  },
  {
    id: 'security_report',
    name: 'Security Report',
    icon: ShieldAlert,
    description: 'Full WiFi security assessment',
    helpText: 'Generates a comprehensive WiFi security report by scanning all nearby networks, cross-referencing with cracked passwords, and assigning risk levels (CRITICAL, HIGH, MEDIUM, LOW) based on encryption type and vulnerabilities.',
    category: 'report',
    fields: [],
    action: () => callWifiTool('security_report', {}),
  },
]

const CATEGORIES = [
  { id: 'recon', label: 'Recon', icon: Radio },
  { id: 'attack', label: 'Attack', icon: Zap },
  { id: 'crack', label: 'Crack', icon: Lock },
  { id: 'rogue', label: 'Rogue AP', icon: Ghost },
  { id: 'report', label: 'Reports', icon: FileSearch },
] as const

const FIELD_LABELS: Record<keyof WifiFormState, { label: string; placeholder: string; tooltip: string }> = {
  bssid: { label: 'BSSID', placeholder: 'AA:BB:CC:DD:EE:FF', tooltip: 'MAC address of the target access point' },
  channel: { label: 'Channel', placeholder: '1-14', tooltip: 'WiFi channel (1-14 for 2.4GHz, 36-165 for 5GHz)' },
  clientMac: { label: 'Client MAC', placeholder: 'Optional', tooltip: 'MAC of specific client to target (empty = broadcast)' },
  duration: { label: 'Duration (s)', placeholder: '30', tooltip: 'How long to run the operation in seconds' },
  count: { label: 'Packet Count', placeholder: '10', tooltip: 'Number of packets to send' },
  timeout: { label: 'Timeout (s)', placeholder: '120', tooltip: 'Maximum time to wait for results' },
  ssid: { label: 'SSID', placeholder: 'NetworkName', tooltip: 'WiFi network name to target or clone' },
  captureFile: { label: 'Capture File', placeholder: '/path/to/file.cap', tooltip: 'Path to handshake (.cap) or PMKID (.16800) file' },
  wordlist: { label: 'Wordlist', placeholder: 'Default: passwords.txt', tooltip: 'Path to wordlist file (empty = use Bjorn default)' },
  pixieDust: { label: 'Pixie Dust', placeholder: '', tooltip: 'Use Pixie Dust attack for faster WPS cracking' },
}

export function WifiPage() {
  const statusFetcher = useCallback(() => fetchStatus(), [])
  const { data: status } = usePoll<BjornStatus>(statusFetcher, 10000)
  const [form, setForm] = useState<WifiFormState>(DEFAULT_FORM)
  const [selectedTool, setSelectedTool] = useState<WifiTool | null>(null)
  const [result, setResult] = useState<Record<string, unknown> | null>(null)
  const [running, setRunning] = useState(false)
  const [resultError, setResultError] = useState('')

  const updateField = (key: keyof WifiFormState, value: string | boolean) => {
    setForm(prev => ({ ...prev, [key]: value }))
  }

  const executeTool = async (tool: WifiTool) => {
    setRunning(true)
    setResult(null)
    setResultError('')
    try {
      const res = await tool.action(form)
      setResult(res as Record<string, unknown>)
    } catch (e) {
      setResultError(e instanceof Error ? e.message : String(e))
    } finally {
      setRunning(false)
    }
  }

  return (
    <TooltipProvider>
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <Wifi className="size-6" /> WiFi Security Tools
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              13 offensive WiFi tools using wlan1 (external adapter)
            </p>
          </div>
          <Badge variant={status ? 'default' : 'secondary'}>
            {status?.bjorn_status || '...'}
          </Badge>
        </div>

        <Tabs defaultValue="recon">
          <TabsList className="flex-wrap h-auto gap-1">
            {CATEGORIES.map(cat => (
              <TabsTrigger key={cat.id} value={cat.id} className="gap-1.5">
                <cat.icon className="size-3.5" />
                {cat.label}
              </TabsTrigger>
            ))}
          </TabsList>

          {CATEGORIES.map(cat => (
            <TabsContent key={cat.id} value={cat.id}>
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                {WIFI_TOOLS.filter(t => t.category === cat.id).map(tool => (
                  <Card
                    key={tool.id}
                    className={`bg-card/60 cursor-pointer transition-all hover:ring-1 hover:ring-primary/50 ${
                      selectedTool?.id === tool.id ? 'ring-1 ring-primary' : ''
                    }`}
                    onClick={() => setSelectedTool(tool)}
                  >
                    <CardHeader className="pb-2 pt-4 px-4">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm flex items-center gap-2">
                          <tool.icon className="size-4 text-primary" />
                          {tool.name}
                        </CardTitle>
                        <Tooltip>
                          <TooltipTrigger className="inline-flex">
                            <Info className="size-3.5 text-muted-foreground cursor-help" />
                          </TooltipTrigger>
                          <TooltipContent side="left" className="max-w-xs text-xs">
                            {tool.helpText}
                          </TooltipContent>
                        </Tooltip>
                      </div>
                      <CardDescription className="text-xs">
                        {tool.description}
                      </CardDescription>
                    </CardHeader>
                  </Card>
                ))}
              </div>
            </TabsContent>
          ))}
        </Tabs>

        {selectedTool && (
          <>
            <Separator />
            <Card className="bg-card/60">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <selectedTool.icon className="size-4 text-primary" />
                    {selectedTool.name}
                  </CardTitle>
                  <Badge variant="outline" className="text-xs">
                    wifi_{selectedTool.id}
                  </Badge>
                </div>
                <CardDescription className="text-xs">
                  {selectedTool.helpText}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {selectedTool.fields.length > 0 && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {selectedTool.fields.map(field => {
                      const meta = FIELD_LABELS[field]
                      if (field === 'pixieDust') {
                        return (
                          <div key={field} className="flex items-center gap-2">
                            <Tooltip>
                              <TooltipTrigger className="inline-flex">
                                <label className="text-xs text-muted-foreground cursor-help flex items-center gap-1">
                                  {meta.label}
                                  <Info className="size-3" />
                                </label>
                              </TooltipTrigger>
                              <TooltipContent className="text-xs">{meta.tooltip}</TooltipContent>
                            </Tooltip>
                            <input
                              type="checkbox"
                              checked={form.pixieDust}
                              onChange={e => updateField('pixieDust', e.target.checked)}
                              className="rounded"
                            />
                          </div>
                        )
                      }
                      return (
                        <div key={field}>
                          <Tooltip>
                            <TooltipTrigger className="inline-flex">
                              <label className="text-xs text-muted-foreground mb-1 block cursor-help flex items-center gap-1">
                                {meta.label}
                                <Info className="size-3" />
                              </label>
                            </TooltipTrigger>
                            <TooltipContent className="text-xs">{meta.tooltip}</TooltipContent>
                          </Tooltip>
                          <input
                            type="text"
                            value={String(form[field])}
                            onChange={e => updateField(field, e.target.value)}
                            placeholder={meta.placeholder}
                            className="w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm font-mono"
                          />
                        </div>
                      )
                    })}
                  </div>
                )}
                <div className="flex items-center gap-3">
                  <Button
                    size="sm"
                    onClick={() => executeTool(selectedTool)}
                    disabled={running}
                  >
                    {running ? (
                      <RefreshCw className="size-3.5 mr-1.5 animate-spin" />
                    ) : (
                      <Play className="size-3.5 mr-1.5" />
                    )}
                    {running ? 'Running...' : 'Execute'}
                  </Button>
                  {resultError && (
                    <span className="text-xs text-destructive">{resultError}</span>
                  )}
                </div>
              </CardContent>
            </Card>
          </>
        )}

        {result && (
          <Card className="bg-card/60">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs text-muted-foreground">Result</CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="max-h-96">
                <pre className="text-xs font-mono whitespace-pre-wrap text-muted-foreground">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </ScrollArea>
            </CardContent>
          </Card>
        )}
      </div>
    </TooltipProvider>
  )
}
