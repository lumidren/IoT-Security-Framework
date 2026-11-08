import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { auth } from '@/auth';
import { AppShell } from '@/components/layout/app-shell';
import { SIDEBAR_COOKIE } from '@/lib/constants';
import { userFromSession } from '@/lib/session-user';
import { SessionProvider } from '@/providers/session-context';
import { WsProvider } from '@/providers/ws-provider';

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const session = await auth();
  if (!session?.user) redirect('/signin');
  const cookieStore = await cookies();
  const defaultCollapsed = cookieStore.get(SIDEBAR_COOKIE)?.value === 'collapsed';
  const user = userFromSession(session);

  return (
    <SessionProvider user={user}>
      <WsProvider>
        <AppShell defaultCollapsed={defaultCollapsed}>{children}</AppShell>
      </WsProvider>
    </SessionProvider>
  );
}
