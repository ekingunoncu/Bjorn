import type { Page } from '@/App'
import {
  Sidebar,
  SidebarContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
} from '@/components/ui/sidebar'
import {
  LayoutDashboard,
  Terminal,
  Network,
  KeyRound,
  FolderOpen,
  Settings,
  Wrench,
  Skull,
  Wifi,
} from 'lucide-react'

const NAV_ITEMS: { id: Page; label: string; icon: typeof LayoutDashboard; group: string; desc: string }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, group: 'Overview', desc: 'Status overview and controls' },
  { id: 'console', label: 'Console', icon: Terminal, group: 'Overview', desc: 'Live Bjorn logs' },
  { id: 'network', label: 'Network', icon: Network, group: 'Recon', desc: 'Discovered hosts and manual attacks' },
  { id: 'credentials', label: 'Credentials', icon: KeyRound, group: 'Recon', desc: 'Cracked passwords by service' },
  { id: 'loot', label: 'Loot', icon: FolderOpen, group: 'Recon', desc: 'Stolen files from targets' },
  { id: 'wifi', label: 'WiFi Tools', icon: Wifi, group: 'Attack', desc: '13 WiFi security testing tools' },
  { id: 'toollog', label: 'MCP Tools', icon: Wrench, group: 'System', desc: 'MCP tool call history' },
  { id: 'config', label: 'Config', icon: Settings, group: 'System', desc: 'Settings, WiFi, system management' },
]

interface Props {
  currentPage: Page
  onNavigate: (page: Page) => void
}

export function AppSidebar({ currentPage, onNavigate }: Props) {
  const groups = [...new Set(NAV_ITEMS.map(i => i.group))]

  return (
    <Sidebar variant="inset" collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              className="cursor-pointer"
              onClick={() => onNavigate('dashboard')}
            >
              <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <Skull className="size-5" />
              </div>
              <div className="flex flex-col gap-0.5 leading-none">
                <span className="font-bold text-base">Bjorn</span>
                <span className="text-xs text-muted-foreground">Cyberviking</span>
              </div>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        {groups.map(group => (
          <SidebarGroup key={group}>
            <SidebarGroupLabel>{group}</SidebarGroupLabel>
            <SidebarMenu>
              {NAV_ITEMS.filter(i => i.group === group).map(item => (
                <SidebarMenuItem key={item.id}>
                  <SidebarMenuButton
                    isActive={currentPage === item.id}
                    onClick={() => onNavigate(item.id)}
                    tooltip={`${item.label} — ${item.desc}`}
                    className="cursor-pointer"
                  >
                    <item.icon className="size-4" />
                    <span>{item.label}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroup>
        ))}
      </SidebarContent>
      <SidebarFooter>
        <div className="px-2 py-1 text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">
          Bjorn v2.0
        </div>
      </SidebarFooter>
    </Sidebar>
  )
}
