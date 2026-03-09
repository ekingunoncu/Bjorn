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
} from 'lucide-react'

const NAV_ITEMS: { id: Page; label: string; icon: typeof LayoutDashboard; group: string }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, group: 'Overview' },
  { id: 'console', label: 'Console', icon: Terminal, group: 'Overview' },
  { id: 'network', label: 'Network', icon: Network, group: 'Recon' },
  { id: 'credentials', label: 'Credentials', icon: KeyRound, group: 'Recon' },
  { id: 'loot', label: 'Loot', icon: FolderOpen, group: 'Recon' },
  { id: 'toollog', label: 'MCP Tools', icon: Wrench, group: 'System' },
  { id: 'config', label: 'Config', icon: Settings, group: 'System' },
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
                    tooltip={item.label}
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
