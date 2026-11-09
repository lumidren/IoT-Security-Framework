import type { Metadata } from 'next';
import { KeyRoundIcon, ShieldCheckIcon } from 'lucide-react';
import { oidcConfigured, signIn } from '@/auth';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { DEMO_TENANT_NAME, isMockMode } from '@/lib/env';
import { ROLE_LABEL, RoleSchema, isRole } from '@/lib/rbac-values';
import { safeRedirectPath } from '@/lib/safe-redirect';

export const metadata: Metadata = { title: 'Sign in' };

const ERROR_MESSAGES: Record<string, string> = {
  Configuration: 'The identity provider is not configured correctly. Contact your administrator.',
  AccessDenied: 'Your account is not allowed to access this console.',
  Verification: 'The sign-in link has expired. Try again.',
  OAuthSignin: 'Could not start the sign-in with the identity provider.',
  OAuthCallbackError: 'The identity provider rejected the sign-in. Try again.',
  OAuthCallback: 'The identity provider rejected the sign-in. Try again.',
  CredentialsSignin: 'The demo role you picked is not valid.',
  SessionRequired: 'Sign in to continue.',
  Default: 'Sign-in failed. Try again.',
};

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ callbackUrl?: string; error?: string }>;
}) {
  const params = await searchParams;
  const callbackUrl = safeRedirectPath(params.callbackUrl);
  const errorMessage = params.error
    ? (ERROR_MESSAGES[params.error] ?? ERROR_MESSAGES['Default'])
    : null;

  async function signInWithSso() {
    'use server';
    await signIn('oidc', { redirectTo: callbackUrl });
  }

  async function signInDemo(formData: FormData) {
    'use server';
    const role = formData.get('role');
    await signIn('demo', { role: isRole(role) ? role : 'viewer', redirectTo: callbackUrl });
  }

  return (
    <main id="main-content" className="flex min-h-dvh items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="items-center text-center">
          <span className="mb-2 flex size-12 items-center justify-center rounded-xl bg-primary text-primary-foreground">
            <ShieldCheckIcon className="size-7" aria-hidden="true" />
          </span>
          <CardTitle className="text-xl">IronMesh Console</CardTitle>
          <CardDescription>
            Sign in with your organisation account to manage the fleet.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {errorMessage && (
            <Alert variant="destructive">
              <AlertTitle>Sign-in failed</AlertTitle>
              <AlertDescription>{errorMessage}</AlertDescription>
            </Alert>
          )}

          {oidcConfigured ? (
            <form action={signInWithSso}>
              <Button type="submit" className="w-full" size="lg">
                <KeyRoundIcon aria-hidden="true" /> Continue with single sign-on
              </Button>
            </form>
          ) : (
            <Alert variant={isMockMode ? 'info' : 'warning'}>
              <AlertTitle>Single sign-on is not configured</AlertTitle>
              <AlertDescription>
                Set <code className="font-mono text-xs">CONSOLE_OIDC_ISSUER</code>,{' '}
                <code className="font-mono text-xs">CONSOLE_OIDC_CLIENT_ID</code> and{' '}
                <code className="font-mono text-xs">CONSOLE_OIDC_CLIENT_SECRET</code> to enable it.
              </AlertDescription>
            </Alert>
          )}

          {isMockMode && (
            <form
              action={signInDemo}
              className="flex flex-col gap-3 rounded-lg border border-dashed p-4"
            >
              <div>
                <p className="font-medium">Demo sign-in</p>
                <p className="text-sm text-muted-foreground">
                  Explore {DEMO_TENANT_NAME} with mock data. Pick a role to see how permissions
                  change the console.
                </p>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="demo-role">Role</Label>
                <select
                  id="demo-role"
                  name="role"
                  defaultValue="operator"
                  className="h-9 rounded-md border border-input bg-background px-3 text-sm focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
                >
                  {RoleSchema.options.map((role) => (
                    <option key={role} value={role}>
                      {ROLE_LABEL[role]}
                    </option>
                  ))}
                </select>
              </div>
              <Button type="submit" variant="secondary" className="w-full">
                Sign in to the demo
              </Button>
            </form>
          )}

          <p className="text-center text-xs text-muted-foreground">
            Access is restricted to authorised fleet operators. All actions are audited.
          </p>
        </CardContent>
      </Card>
    </main>
  );
}
