import { useCallback } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { usePoll } from '@/hooks/use-poll'
import { api } from '@/lib/api'
import type { ToolCallEntry } from '@/lib/api'
import { Wrench, RefreshCw, CheckCircle, XCircle } from 'lucide-react'

function ToolEntry({ entry }: { entry: ToolCallEntry }) {
  const hasArgs = entry.args && Object.keys(entry.args).length > 0

  return (
    <Card className={`bg-background/50 border-l-2 ${
      entry.success ? 'border-l-primary' : 'border-l-destructive'
    }`}>
      <CardContent className="py-3 px-4 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {entry.success ? (
              <CheckCircle className="size-3.5 text-green-400" />
            ) : (
              <XCircle className="size-3.5 text-destructive" />
            )}
            <span className="font-mono text-sm font-medium text-primary">
              {entry.tool}
            </span>
            <Badge variant={entry.success ? 'default' : 'destructive'} className="text-[10px] px-1.5 py-0">
              {entry.success ? 'OK' : 'ERR'}
            </Badge>
          </div>
          <span className="text-xs text-muted-foreground font-mono">
            {entry.timestamp}
          </span>
        </div>
        {hasArgs && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-0.5">Args</div>
            <pre className="text-xs font-mono bg-muted/30 rounded p-2 overflow-x-auto max-h-24">
              {JSON.stringify(entry.args, null, 2)}
            </pre>
          </div>
        )}
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-0.5">Result</div>
          <pre className="text-xs font-mono bg-muted/30 rounded p-2 overflow-x-auto max-h-48 text-muted-foreground">
            {entry.result_preview}
          </pre>
        </div>
      </CardContent>
    </Card>
  )
}

export function ToolLogPage() {
  const fetcher = useCallback(() => api.getToolLog(), [])
  const { data: entries, loading, refresh } = usePoll<ToolCallEntry[]>(fetcher, 5000)
  const reversed = entries ? [...entries].reverse() : []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Wrench className="size-6" /> MCP Tool Calls
        </h1>
        <div className="flex items-center gap-2">
          <Badge variant="secondary">{entries?.length ?? 0} calls</Badge>
          <Button size="sm" variant="ghost" onClick={refresh}>
            <RefreshCw className="size-3.5 mr-1.5" /> Refresh
          </Button>
        </div>
      </div>

      <ScrollArea className="h-[calc(100vh-160px)]">
        {loading && !entries && (
          <div className="text-sm text-muted-foreground">Loading...</div>
        )}
        {reversed.length > 0 ? (
          <div className="space-y-2">
            {reversed.map((entry, i) => (
              <ToolEntry key={`${entry.timestamp}-${i}`} entry={entry} />
            ))}
          </div>
        ) : !loading ? (
          <Card className="bg-card/60">
            <CardContent className="py-12 text-center text-muted-foreground text-sm">
              <Wrench className="size-10 mx-auto mb-3 opacity-30" />
              <div>No MCP tool calls yet.</div>
              <div className="text-xs mt-1">
                Connect an MCP client (Claude Code / Claude Desktop) and call tools to see them here.
              </div>
            </CardContent>
          </Card>
        ) : null}
      </ScrollArea>
    </div>
  )
}
