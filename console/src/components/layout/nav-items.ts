import {
  BellIcon,
  ClipboardListIcon,
  CpuIcon,
  FactoryIcon,
  LayoutDashboardIcon,
  RocketIcon,
  ScrollTextIcon,
  ShieldBanIcon,
  UserCogIcon,
  type LucideIcon,
} from 'lucide-react';

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Short keywords for the command palette. */
  keywords?: string[];
}

export const NAV_ITEMS: NavItem[] = [
  {
    href: '/',
    label: 'Overview',
    icon: LayoutDashboardIcon,
    keywords: ['home', 'fleet', 'dashboard'],
  },
  { href: '/devices', label: 'Devices', icon: CpuIcon, keywords: ['fleet', 'inventory'] },
  {
    href: '/provisioning',
    label: 'Provisioning',
    icon: FactoryIcon,
    keywords: ['enroll', 'approve'],
  },
  {
    href: '/campaigns',
    label: 'Campaigns',
    icon: RocketIcon,
    keywords: ['ota', 'firmware', 'rollout'],
  },
  {
    href: '/policy',
    label: 'Policy',
    icon: ScrollTextIcon,
    keywords: ['rego', 'opa', 'mqtt', 'acl'],
  },
  { href: '/alerts', label: 'Alerts', icon: BellIcon, keywords: ['anomaly', 'incidents'] },
  {
    href: '/quarantine',
    label: 'Quarantine',
    icon: ShieldBanIcon,
    keywords: ['isolated', 'revoked'],
  },
  { href: '/audit', label: 'Audit log', icon: ClipboardListIcon, keywords: ['events', 'export'] },
  {
    href: '/settings/access',
    label: 'Access',
    icon: UserCogIcon,
    keywords: ['users', 'roles', 'api keys', 'settings'],
  },
];

export function isActivePath(pathname: string, href: string): boolean {
  if (href === '/') return pathname === '/';
  return pathname === href || pathname.startsWith(`${href}/`);
}
