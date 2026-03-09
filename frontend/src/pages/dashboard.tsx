import { useCallback, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { EpaperWidget } from '@/components/epaper-widget'
import { usePoll } from '@/hooks/use-poll'
import { api } from '@/lib/api'
import type { BjornStatus } from '@/lib/api'
import {
  Crosshair, Network, ShieldAlert, KeyRound,
  FolderOpen, Skull, Play, Square, RotateCcw,
  Power, PowerOff,
} from 'lucide-react'

const STAT_CARDS: {
  key: keyof BjornStatus
  label: string
  icon: typeof Network
  color: string
}[] = [
  { key: 'alive_hosts', label: 'Alive Hosts', icon: Network, color: 'text-green-400' },
  { key: 'targets', label: 'Targets', icon: Crosshair, color: 'text-blue-400' },
  { key: 'open_ports', label: 'Open Ports', icon: Network, color: 'text-cyan-400' },
  { key: 'vulnerabilities', label: 'Vulns', icon: ShieldAlert, color: 'text-red-400' },
  { key: 'credentials', label: 'Creds', icon: KeyRound, color: 'text-yellow-400' },
  { key: 'stolen_data', label: 'Data Stolen', icon: FolderOpen, color: 'text-purple-400' },
  { key: 'zombies', label: 'Zombies', icon: Skull, color: 'text-orange-400' },
]

export function DashboardPage() {
  const fetcher = useCallback(() => api.getStatus(), [])
  const { data: status, error, loading } = usePoll<BjornStatus>(fetcher, 5000)
  const [actionMsg, setActionMsg] = useState('')

  const doAction = async (label: string, fn: () => Promise<unknown>) => {
    try {
      await fn()
      setActionMsg(`${label} sent`)
      setTimeout(() => setActionMsg(''), 3000)
    } catch (e) {
      setActionMsg(`Error: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const orchRunning = status?.bjorn_status === 'Running'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            {status?.status_text || 'Loading...'}
          </p>
        </div>
        <Badge
          variant={orchRunning ? 'default' : 'secondary'}
          className={orchRunning ? 'bg-green-600 hover:bg-green-700' : ''}
        >
          {status?.bjorn_status || 'Unknown'}
        </Badge>
      </div>

      {error && (
        <Card className="border-destructive">
          <CardContent className="pt-4 text-sm text-destructive">
            Connection error: {error}. Is Bjorn running?
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        {STAT_CARDS.map(({ key, label, icon: Icon, color }) => (
          <Card key={key} className="bg-card/60">
            <CardHeader className="pb-1 pt-3 px-4">
              <CardTitle className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                <Icon className={`size-3.5 ${color}`} />
                {label}
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-3">
              <div className="text-2xl font-bold tabular-nums">
                {loading ? '—' : String(status?.[key] ?? 0)}
              </div>
            </CardContent>
          </Card>
        ))}
        <Card className="bg-card/60">
          <CardHeader className="pb-1 pt-3 px-4">
            <CardTitle className="text-xs font-medium text-muted-foreground">Level / Coins</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3">
            <div className="text-2xl font-bold tabular-nums">
              {loading ? '—' : `${status?.level ?? 0} / ${status?.coins ?? 0}`}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* e-Paper visible on smaller screens */}
      <div className="xl:hidden">
        <EpaperWidget />
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Controls</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button
            size="sm"
            variant={orchRunning ? 'destructive' : 'default'}
            onClick={() => doAction(
              orchRunning ? 'Stop' : 'Start',
              orchRunning ? api.stopOrchestrator : api.startOrchestrator
            )}
          >
            {orchRunning ? <Square className="size-3.5 mr-1.5" /> : <Play className="size-3.5 mr-1.5" />}
            {orchRunning ? 'Stop' : 'Start'} Orchestrator
          </Button>
          <Button size="sm" variant="secondary" onClick={() => doAction('Restart', api.restartService)}>
            <RotateCcw className="size-3.5 mr-1.5" /> Restart
          </Button>
          <Button size="sm" variant="secondary" onClick={() => doAction('Reboot', api.reboot)}>
            <Power className="size-3.5 mr-1.5" /> Reboot
          </Button>
          <Button size="sm" variant="destructive" onClick={() => doAction('Shutdown', api.shutdown)}>
            <PowerOff className="size-3.5 mr-1.5" /> Shutdown
          </Button>
          {actionMsg && (
            <span className="text-xs text-muted-foreground self-center ml-2">{actionMsg}</span>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
