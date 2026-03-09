import { useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { usePoll } from '@/hooks/use-poll'
import { api } from '@/lib/api'
import { KeyRound, RefreshCw } from 'lucide-react'

export function CredentialsPage() {
  const fetcher = useCallback(() => api.getCredentialsHtml(), [])
  const { data: html, loading, refresh } = usePoll<string>(fetcher, 15000)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <KeyRound className="size-6" /> Credentials
        </h1>
        <Button size="sm" variant="ghost" onClick={refresh}>
          <RefreshCw className="size-3.5 mr-1.5" /> Refresh
        </Button>
      </div>
      <Card className="bg-card/60">
        <CardHeader className="pb-2">
          <CardTitle className="text-xs text-muted-foreground">Cracked Passwords</CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[calc(100vh-220px)]">
            {loading && <div className="text-sm text-muted-foreground">Loading...</div>}
            {html ? (
              <div
                className="prose prose-invert prose-sm max-w-none [&_table]:w-full [&_table]:text-xs [&_table]:border-collapse [&_th]:bg-muted/50 [&_th]:px-3 [&_th]:py-2 [&_th]:text-left [&_th]:font-medium [&_th]:text-muted-foreground [&_th]:border [&_th]:border-border [&_td]:px-3 [&_td]:py-1.5 [&_td]:border [&_td]:border-border [&_td]:font-mono [&_h2]:text-primary [&_h2]:text-sm [&_h2]:mt-4 [&_h2]:mb-2"
                dangerouslySetInnerHTML={{ __html: html }}
              />
            ) : !loading ? (
              <div className="text-sm text-muted-foreground py-8 text-center">
                No credentials cracked yet.
              </div>
            ) : null}
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  )
}
