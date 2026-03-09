import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Monitor } from 'lucide-react'

export function EpaperWidget() {
  const [ts, setTs] = useState(Date.now())

  useEffect(() => {
    const id = setInterval(() => setTs(Date.now()), 3000)
    return () => clearInterval(id)
  }, [])

  return (
    <Card className="bg-card/50 backdrop-blur">
      <CardHeader className="pb-2 pt-3 px-3">
        <CardTitle className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
          <Monitor className="size-3.5" />
          e-Paper Display
        </CardTitle>
      </CardHeader>
      <CardContent className="px-3 pb-3">
        <div className="rounded-md overflow-hidden border border-border bg-white">
          <img
            src={`/screen.png?t=${ts}`}
            alt="Bjorn e-Paper Display"
            className="w-full h-auto"
            style={{ imageRendering: 'pixelated' }}
          />
        </div>
      </CardContent>
    </Card>
  )
}
