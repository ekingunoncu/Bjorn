import { useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { usePoll } from '@/hooks/use-poll'
import { api } from '@/lib/api'
import { Terminal, RefreshCw } from 'lucide-react'

export function ConsolePage() {
  const fetcher = useCallback(() => api.getLogs(), [])
  const { data: logs, loading, refresh } = usePoll<string>(fetcher, 3000)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Terminal className="size-6" /> Console
        </h1>
        <Button size="sm" variant="ghost" onClick={refresh}>
          <RefreshCw className="size-3.5 mr-1.5" /> Refresh
        </Button>
      </div>
      <Card className="bg-card/60">
        <CardHeader className="pb-1">
          <CardTitle className="text-xs text-muted-foreground">Live Logs</CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[calc(100vh-200px)]">
            <pre className="text-xs font-mono whitespace-pre-wrap text-muted-foreground leading-relaxed">
              {loading ? 'Loading logs...' : (logs || 'No logs available')}
            </pre>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  )
}
