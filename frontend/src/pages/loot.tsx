import { useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { usePoll } from '@/hooks/use-poll'
import { api } from '@/lib/api'
import type { LootFile } from '@/lib/api'
import { FolderOpen, File, Folder, Download, RefreshCw } from 'lucide-react'

function FileTree({ files, depth = 0 }: { files: LootFile[]; depth?: number }) {
  return (
    <div style={{ paddingLeft: depth * 16 }}>
      {files.map(file => (
        <div key={file.name}>
          <div className="flex items-center gap-2 py-1 px-2 rounded hover:bg-muted/50 text-sm">
            {file.is_directory ? (
              <Folder className="size-4 text-primary shrink-0" />
            ) : (
              <File className="size-4 text-muted-foreground shrink-0" />
            )}
            <span className="truncate font-mono text-xs">{file.name}</span>
            {!file.is_directory && file.path && (
              <a
                href={`/download_file?path=${encodeURIComponent(file.path)}`}
                className="ml-auto shrink-0"
              >
                <Button size="sm" variant="ghost" className="h-6 px-2">
                  <Download className="size-3" />
                </Button>
              </a>
            )}
          </div>
          {file.is_directory && file.children && (
            <FileTree files={file.children} depth={depth + 1} />
          )}
        </div>
      ))}
    </div>
  )
}

export function LootPage() {
  const fetcher = useCallback(() => api.getLoot(), [])
  const { data: files, loading, refresh } = usePoll<LootFile[]>(fetcher, 15000)

  const totalFiles = (list: LootFile[]): number =>
    list.reduce((sum, f) =>
      sum + (f.is_directory ? totalFiles(f.children || []) : 1), 0)

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <FolderOpen className="size-6" /> Loot
        </h1>
        <Button size="sm" variant="ghost" onClick={refresh}>
          <RefreshCw className="size-3.5 mr-1.5" /> Refresh
        </Button>
      </div>
      <Card className="bg-card/60">
        <CardHeader className="pb-2">
          <CardTitle className="text-xs text-muted-foreground">
            Stolen Files {files && `(${totalFiles(files)} files)`}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[calc(100vh-220px)]">
            {loading && <div className="text-sm text-muted-foreground">Loading...</div>}
            {files && files.length > 0 ? (
              <FileTree files={files} />
            ) : !loading ? (
              <div className="text-sm text-muted-foreground py-8 text-center">
                No loot collected yet.
              </div>
            ) : null}
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  )
}
