import { useCallback, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { usePoll } from '@/hooks/use-poll'
import { api } from '@/lib/api'
import type { NetKBJson } from '@/lib/api'
import { Network as NetworkIcon, RefreshCw, Crosshair } from 'lucide-react'

export function NetworkPage() {
  const netkbFetcher = useCallback(() => api.getNetkbJson(), [])
  const { data: netkb, loading, refresh } = usePoll<NetKBJson>(netkbFetcher, 10000)
  const [selectedIp, setSelectedIp] = useState<string | null>(null)
  const [attackAction, setAttackAction] = useState('')
  const [attackPort, setAttackPort] = useState('')
  const [attackMsg, setAttackMsg] = useState('')

  const executeAttack = async () => {
    if (!selectedIp || !attackAction) return
    try {
      setAttackMsg('Executing...')
      await api.executeAttack(selectedIp, attackPort, attackAction)
      setAttackMsg('Attack executed')
      setTimeout(() => setAttackMsg(''), 3000)
    } catch (e) {
      setAttackMsg(`Error: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <NetworkIcon className="size-6" /> Network
        </h1>
        <Button size="sm" variant="ghost" onClick={refresh}>
          <RefreshCw className="size-3.5 mr-1.5" /> Refresh
        </Button>
      </div>

      <Tabs defaultValue="hosts">
        <TabsList>
          <TabsTrigger value="hosts">Live Hosts</TabsTrigger>
          <TabsTrigger value="attack">Manual Attack</TabsTrigger>
        </TabsList>

        <TabsContent value="hosts">
          <Card className="bg-card/60">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">
                Network Knowledge Base
                {netkb && <Badge variant="secondary" className="ml-2">{netkb.ips.length} hosts</Badge>}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {loading && <div className="text-sm text-muted-foreground">Loading...</div>}
              {netkb && netkb.ips.length === 0 && (
                <div className="text-sm text-muted-foreground py-8 text-center">
                  No live hosts discovered yet. Start the orchestrator to begin scanning.
                </div>
              )}
              <ScrollArea className="h-[calc(100vh-280px)]">
                <div className="space-y-2">
                  {netkb?.ips.map(ip => (
                    <Card
                      key={ip}
                      className={`bg-background/50 cursor-pointer transition-colors hover:bg-background/80 ${
                        selectedIp === ip ? 'ring-1 ring-primary' : ''
                      }`}
                      onClick={() => setSelectedIp(ip)}
                    >
                      <CardContent className="py-3 px-4">
                        <div className="flex items-center justify-between">
                          <div className="font-mono text-sm font-medium">{ip}</div>
                          <div className="flex gap-1 flex-wrap justify-end">
                            {(netkb.ports[ip] || []).filter(Boolean).map(port => (
                              <Badge key={port} variant="outline" className="text-xs font-mono">
                                {port}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="attack">
          <Card className="bg-card/60">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-1.5">
                <Crosshair className="size-4" /> Manual Attack
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Target IP</label>
                  <select
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    value={selectedIp || ''}
                    onChange={e => {
                      setSelectedIp(e.target.value)
                      setAttackPort(netkb?.ports[e.target.value]?.[0] || '')
                    }}
                  >
                    <option value="">Select IP...</option>
                    {netkb?.ips.map(ip => (
                      <option key={ip} value={ip}>{ip}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Port</label>
                  <select
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    value={attackPort}
                    onChange={e => setAttackPort(e.target.value)}
                  >
                    {selectedIp && netkb?.ports[selectedIp]?.map(port => (
                      <option key={port} value={port}>{port}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Action</label>
                  <select
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    value={attackAction}
                    onChange={e => setAttackAction(e.target.value)}
                  >
                    <option value="">Select action...</option>
                    {netkb?.actions.map(action => (
                      <option key={action} value={action}>{action}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Button
                  size="sm"
                  disabled={!selectedIp || !attackAction}
                  onClick={executeAttack}
                >
                  <Crosshair className="size-3.5 mr-1.5" /> Execute
                </Button>
                {attackMsg && (
                  <span className="text-xs text-muted-foreground">{attackMsg}</span>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
