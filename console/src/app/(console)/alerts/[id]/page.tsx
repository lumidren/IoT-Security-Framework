import type { Metadata } from 'next';
import { AlertDetailView } from '@/components/alerts/alert-detail-view';

export const metadata: Metadata = { title: 'Alert' };

export default async function AlertPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return <AlertDetailView id={id} />;
}
