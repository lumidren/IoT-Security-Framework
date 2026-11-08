import type { Metadata } from 'next';
import Link from 'next/link';
import { LockIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export const metadata: Metadata = { title: 'Forbidden' };

export default function ForbiddenPage() {
  return (
    <main id="main-content" className="flex min-h-dvh items-center justify-center p-4">
      <Card className="w-full max-w-md text-center">
        <CardHeader className="items-center">
          <span className="mb-2 flex size-12 items-center justify-center rounded-xl bg-muted">
            <LockIcon className="size-6" aria-hidden="true" />
          </span>
          <CardTitle className="text-xl">You do not have access</CardTitle>
          <CardDescription>
            Your role in this tenant does not permit the page or action you requested. Ask a tenant
            owner to adjust your role if you need it.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 sm:flex-row sm:justify-center">
          <Button asChild>
            <Link href="/">Back to overview</Link>
          </Button>
          <Button asChild variant="outline">
            <Link href="/signin">Switch account</Link>
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
