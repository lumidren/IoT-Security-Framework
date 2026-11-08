'use client';

import * as React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  MenuIcon,
  PanelLeftCloseIcon,
  PanelLeftOpenIcon,
  SearchIcon,
  ShieldCheckIcon,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { CommandPalette } from '@/components/layout/command-palette';
import { NAV_ITEMS, isActivePath } from '@/components/layout/nav-items';
import { TenantBadge } from '@/components/layout/tenant-badge';
import { ThemeToggle } from '@/components/layout/theme-toggle';
import { UserMenu } from '@/components/layout/user-menu';
import { WsStatusIndicator } from '@/components/layout/ws-status';
import { cn } from '@/lib/utils';

import { SIDEBAR_COOKIE } from '@/lib/constants';

function NavLinks({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const pathname = usePathname();
  return (
    <ul className="flex flex-col gap-1">
      {NAV_ITEMS.map((item) => {
        const active = isActivePath(pathname, item.href);
        const link = (
          <Link
            href={item.href}
            onClick={onNavigate}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'flex h-10 items-center gap-3 rounded-md px-3 text-sm font-medium transition-colors',
              'hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-[3px] focus-visible:ring-sidebar-ring focus-visible:outline-none',
              active
                ? 'bg-sidebar-primary text-sidebar-primary-foreground hover:bg-sidebar-primary hover:text-sidebar-primary-foreground'
                : 'text-sidebar-foreground',
              collapsed && 'justify-center px-0',
            )}
          >
            <item.icon className="size-5 shrink-0" aria-hidden="true" />
            <span className={cn(collapsed && 'sr-only')}>{item.label}</span>
          </Link>
        );
        return (
          <li key={item.href}>
            {collapsed ? (
              <Tooltip>
                <TooltipTrigger asChild>{link}</TooltipTrigger>
                <TooltipContent side="right">{item.label}</TooltipContent>
              </Tooltip>
            ) : (
              link
            )}
          </li>
        );
      })}
    </ul>
  );
}

export function AppShell({
  children,
  defaultCollapsed = false,
}: {
  children: React.ReactNode;
  defaultCollapsed?: boolean;
}) {
  const [collapsed, setCollapsed] = React.useState(defaultCollapsed);
  const [mobileOpen, setMobileOpen] = React.useState(false);
  const [paletteOpen, setPaletteOpen] = React.useState(false);
  const pathname = usePathname();

  React.useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  React.useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev;
      document.cookie = `${SIDEBAR_COOKIE}=${next ? 'collapsed' : 'expanded'}; path=/; max-age=31536000; samesite=lax`;
      return next;
    });
  };

  return (
    <TooltipProvider>
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <div className="flex min-h-dvh">
        <aside
          aria-label="Primary"
          className={cn(
            'sticky top-0 hidden h-dvh shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-[width] duration-200 md:flex',
            collapsed ? 'w-16' : 'w-60',
          )}
        >
          <div
            className={cn(
              'flex h-14 items-center gap-2 border-b px-3',
              collapsed && 'justify-center px-0',
            )}
          >
            <Link
              href="/"
              className="flex items-center gap-2 rounded-md font-semibold focus-visible:ring-[3px] focus-visible:outline-none"
              aria-label="IronMesh console home"
            >
              <span className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
                <ShieldCheckIcon className="size-5" aria-hidden="true" />
              </span>
              <span className={cn('text-base', collapsed && 'sr-only')}>IronMesh</span>
            </Link>
          </div>
          <nav aria-label="Main navigation" className="flex-1 overflow-y-auto p-2">
            <NavLinks collapsed={collapsed} />
          </nav>
          <div className={cn('border-t p-2', collapsed && 'flex justify-center')}>
            <Button
              variant="ghost"
              size={collapsed ? 'icon' : 'sm'}
              onClick={toggleCollapsed}
              aria-pressed={collapsed}
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              className={cn(!collapsed && 'w-full justify-start')}
            >
              {collapsed ? <PanelLeftOpenIcon /> : <PanelLeftCloseIcon />}
              {!collapsed && <span>Collapse</span>}
            </Button>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-background/95 px-3 backdrop-blur supports-[backdrop-filter]:bg-background/80 sm:px-4">
            <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
              <SheetTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="md:hidden"
                  aria-label="Open navigation"
                >
                  <MenuIcon />
                </Button>
              </SheetTrigger>
              <SheetContent side="left" className="w-72 p-0">
                <SheetHeader className="border-b">
                  <SheetTitle className="flex items-center gap-2">
                    <ShieldCheckIcon className="size-5" aria-hidden="true" /> IronMesh
                  </SheetTitle>
                  <SheetDescription className="sr-only">Primary navigation</SheetDescription>
                </SheetHeader>
                <nav aria-label="Main navigation" className="p-2">
                  <NavLinks collapsed={false} onNavigate={() => setMobileOpen(false)} />
                </nav>
              </SheetContent>
            </Sheet>

            <Button
              variant="outline"
              className="h-9 w-9 justify-start gap-2 px-0 text-muted-foreground sm:w-64 sm:px-3"
              onClick={() => setPaletteOpen(true)}
              aria-label="Open command palette"
              aria-keyshortcuts="Control+K Meta+K"
            >
              <SearchIcon className="mx-auto size-4 sm:mx-0" aria-hidden="true" />
              <span className="hidden flex-1 text-left text-sm sm:inline">Search or jump to…</span>
              <kbd className="pointer-events-none hidden h-5 items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground sm:inline-flex">
                Ctrl K
              </kbd>
            </Button>

            <div className="ml-auto flex items-center gap-1 sm:gap-2">
              <WsStatusIndicator />
              <TenantBadge />
              <ThemeToggle />
              <UserMenu />
            </div>
          </header>

          <main id="main-content" tabIndex={-1} className="flex-1 p-4 outline-none sm:p-6">
            {children}
          </main>
        </div>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </TooltipProvider>
  );
}
