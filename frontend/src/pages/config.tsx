import { useCallback, useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { usePoll } from '@/hooks/use-poll'
import { api } from '@/lib/api'
import type { ConfigData, WifiNetwork } from '@/lib/api'
import {
  Settings, Save, RotateCcw, Wifi, Trash2, Database,
  HardDrive, RefreshCw, Download,
} from 'lucide-react'

export function ConfigPage() {
  const configFetcher = useCallback(() => api.getConfig(), [])
  const { data: config, refresh: refreshConfig } = usePoll<ConfigData>(configFetcher, 30000)
  const [editConfig, setEditConfig] = useState<ConfigData | null>(null)
  const [saveMsg, setSaveMsg] = useState('')
  const [wifiNets, setWifiNets] = useState<WifiNetwork | null>(null)
  const [wifiSsid, setWifiSsid] = useState('')
  const [wifiPass, setWifiPass] = useState('')
  const [wifiMsg, setWifiMsg] = useState('')
  const [actionMsg, setActionMsg] = useState('')

  useEffect(() => {
    if (config && !editConfig) setEditConfig({ ...config })
  }, [config, editConfig])

  const saveConfig = async () => {
    if (!editConfig) return
    try {
      await api.saveConfig(editConfig)
      setSaveMsg('Saved')
      refreshConfig()
      setTimeout(() => setSaveMsg(''), 3000)
    } catch (e) {
      setSaveMsg(`Error: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const restoreDefaults = async () => {
    try {
      const defaults = await api.restoreDefaultConfig()
      setEditConfig({ ...defaults })
      setSaveMsg('Defaults restored')
      refreshConfig()
      setTimeout(() => setSaveMsg(''), 3000)
    } catch (e) {
      setSaveMsg(`Error: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const scanWifi = async () => {
    try {
      setWifiMsg('Scanning...')
      const nets = await api.scanWifi()
      setWifiNets(nets)
      setWifiMsg('')
    } catch (e) {
      setWifiMsg(`Error: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const connectWifi = async () => {
    try {
      setWifiMsg('Connecting...')
      await api.connectWifi(wifiSsid, wifiPass)
      setWifiMsg('Connected')
      setTimeout(() => setWifiMsg(''), 3000)
    } catch (e) {
      setWifiMsg(`Error: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const doAction = async (label: string, fn: () => Promise<unknown>) => {
    try {
      setActionMsg(`${label}...`)
      const res = await fn()
      const msg = (res as { filename?: string })?.filename
        ? `${label} done: ${(res as { filename: string }).filename}`
        : `${label} done`
      setActionMsg(msg)
      setTimeout(() => setActionMsg(''), 5000)
    } catch (e) {
      setActionMsg(`Error: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const updateField = (key: string, value: string | number | boolean | string[]) => {
    if (!editConfig) return
    setEditConfig({ ...editConfig, [key]: value })
  }

  const isSectionTitle = (key: string) => key.startsWith('__title_')
  const sectionTitle = (key: string) => String(editConfig?.[key] || key)

  const renderConfigField = (key: string, value: unknown) => {
    if (isSectionTitle(key)) return null

    if (typeof value === 'boolean') {
      return (
        <div key={key} className="flex items-center justify-between py-2">
          <label className="text-sm font-mono">{key}</label>
          <Switch
            checked={value}
            onCheckedChange={(v: boolean) => updateField(key, v)}
          />
        </div>
      )
    }
    if (typeof value === 'number') {
      return (
        <div key={key} className="flex items-center justify-between py-2 gap-4">
          <label className="text-sm font-mono shrink-0">{key}</label>
          <input
            type="number"
            value={value}
            onChange={e => updateField(key, Number(e.target.value))}
            className="w-24 rounded-md border border-input bg-background px-2 py-1 text-sm text-right font-mono"
          />
        </div>
      )
    }
    if (Array.isArray(value)) {
      return (
        <div key={key} className="py-2">
          <label className="text-sm font-mono block mb-1">{key}</label>
          <input
            type="text"
            value={value.join(', ')}
            onChange={e => updateField(key, e.target.value.split(',').map(s => s.trim()))}
            className="w-full rounded-md border border-input bg-background px-2 py-1 text-sm font-mono"
          />
        </div>
      )
    }
    return (
      <div key={key} className="flex items-center justify-between py-2 gap-4">
        <label className="text-sm font-mono shrink-0">{key}</label>
        <input
          type="text"
          value={String(value)}
          onChange={e => updateField(key, e.target.value)}
          className="flex-1 min-w-0 rounded-md border border-input bg-background px-2 py-1 text-sm font-mono"
        />
      </div>
    )
  }

  const configSections = () => {
    if (!editConfig) return []
    const sections: { title: string; fields: [string, unknown][] }[] = []
    let current: { title: string; fields: [string, unknown][] } = { title: 'General', fields: [] }

    for (const [key, value] of Object.entries(editConfig)) {
      if (isSectionTitle(key)) {
        if (current.fields.length > 0) sections.push(current)
        current = { title: sectionTitle(key), fields: [] }
      } else {
        current.fields.push([key, value])
      }
    }
    if (current.fields.length > 0) sections.push(current)
    return sections
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Settings className="size-6" /> Configuration
        </h1>
      </div>

      <Tabs defaultValue="config">
        <TabsList>
          <TabsTrigger value="config">Settings</TabsTrigger>
          <TabsTrigger value="wifi">WiFi</TabsTrigger>
          <TabsTrigger value="system">System</TabsTrigger>
        </TabsList>

        <TabsContent value="config">
          <Card className="bg-card/60">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm">Bjorn Settings</CardTitle>
                <div className="flex gap-2 items-center">
                  {saveMsg && <span className="text-xs text-muted-foreground">{saveMsg}</span>}
                  <Button size="sm" variant="ghost" onClick={restoreDefaults}>
                    <RotateCcw className="size-3.5 mr-1" /> Defaults
                  </Button>
                  <Button size="sm" onClick={saveConfig}>
                    <Save className="size-3.5 mr-1" /> Save
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[calc(100vh-280px)]">
                {configSections().map(section => (
                  <div key={section.title} className="mb-4">
                    <h3 className="text-xs font-semibold text-primary uppercase tracking-wider mb-2">
                      {section.title}
                    </h3>
                    <div className="space-y-0 divide-y divide-border/50">
                      {section.fields.map(([k, v]) => renderConfigField(k, v))}
                    </div>
                    <Separator className="mt-4" />
                  </div>
                ))}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="wifi">
          <Card className="bg-card/60">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-1.5">
                <Wifi className="size-4" /> WiFi Connection
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Button size="sm" onClick={scanWifi}>
                  <RefreshCw className="size-3.5 mr-1" /> Scan Networks
                </Button>
                <Button size="sm" variant="destructive" onClick={() => api.disconnectWifi()}>
                  Disconnect
                </Button>
                {wifiMsg && <span className="text-xs text-muted-foreground self-center">{wifiMsg}</span>}
              </div>
              {wifiNets && (
                <>
                  <div className="text-xs text-muted-foreground">
                    Current: <Badge variant="outline">{wifiNets.current_ssid || 'None'}</Badge>
                  </div>
                  <div className="space-y-2">
                    <select
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                      value={wifiSsid}
                      onChange={e => setWifiSsid(e.target.value)}
                    >
                      <option value="">Select network...</option>
                      {wifiNets.networks.filter(Boolean).map(net => (
                        <option key={net} value={net}>{net}</option>
                      ))}
                    </select>
                    <input
                      type="password"
                      placeholder="Password"
                      value={wifiPass}
                      onChange={e => setWifiPass(e.target.value)}
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    />
                    <Button size="sm" onClick={connectWifi} disabled={!wifiSsid}>
                      <Wifi className="size-3.5 mr-1" /> Connect
                    </Button>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="system">
          <Card className="bg-card/60">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">System Management</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {actionMsg && (
                <div className="text-xs text-muted-foreground bg-muted/50 rounded p-2">
                  {actionMsg}
                </div>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <Button size="sm" variant="secondary" onClick={() => doAction('Backup', api.backup)}>
                  <Download className="size-3.5 mr-1.5" /> Create Backup
                </Button>
                <Button size="sm" variant="secondary" onClick={() => doAction('Init CSV', api.initializeCsv)}>
                  <Database className="size-3.5 mr-1.5" /> Initialize CSVs
                </Button>
                <Button size="sm" variant="outline" onClick={() => doAction('Light clear', api.clearFilesLight)}>
                  <Trash2 className="size-3.5 mr-1.5" /> Clear Outputs
                </Button>
                <Button size="sm" variant="destructive" onClick={() => doAction('Full clear', api.clearFiles)}>
                  <HardDrive className="size-3.5 mr-1.5" /> Full Reset
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
