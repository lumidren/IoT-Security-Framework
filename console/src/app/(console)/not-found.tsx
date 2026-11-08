import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { EmptyState } from '@/components/shared/states';

export default function NotFound() {
  return (
    <EmptyState
      title="Page not found"
      description="The page you requested does not exist or has moved."
      action={
        <Button asChild>
          <Link href="/">Back to overview</Link>
        </Button>
      }
    />
  );
}
