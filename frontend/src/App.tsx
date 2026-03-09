import { useState } from 'react'
import { AppSidebar } from '@/components/app-sidebar'
import { EpaperWidget } from '@/components/epaper-widget'
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar'
import { DashboardPage } from '@/pages/dashboard'
import { NetworkPage } from '@/pages/network'
import { CredentialsPage } from '@/pages/credentials'
import { LootPage } from '@/pages/loot'
import { ConfigPage } from '@/pages/config'
import { ToolLogPage } from '@/pages/tool-log'
import { ConsolePage } from '@/pages/console'

export type Page = 'dashboard' | 'console' | 'network' | 'credentials' | 'loot' | 'config' | 'toollog'

function App() {
  const [page, setPage] = useState<Page>('dashboard')

  const renderPage = () => {
    switch (page) {
      case 'dashboard': return <DashboardPage />
      case 'console': return <ConsolePage />
      case 'network': return <NetworkPage />
      case 'credentials': return <CredentialsPage />
      case 'loot': return <LootPage />
      case 'config': return <ConfigPage />
      case 'toollog': return <ToolLogPage />
    }
  }

  return (
    <SidebarProvider>
      <AppSidebar currentPage={page} onNavigate={setPage} />
      <SidebarInset>
        <div className="flex h-screen overflow-hidden">
          <main className="flex-1 overflow-y-auto p-4 md:p-6">
            {renderPage()}
          </main>
          <aside className="hidden xl:flex flex-col w-72 border-l border-border p-4 gap-4 overflow-y-auto">
            <EpaperWidget />
          </aside>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}

export default App
