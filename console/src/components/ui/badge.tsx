import * as React from 'react';
import { Slot } from 'radix-ui';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex w-fit shrink-0 items-center justify-center gap-1 overflow-hidden rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap transition-colors focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 [&>svg]:pointer-events-none [&>svg]:size-3',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        secondary: 'border-transparent bg-secondary text-secondary-foreground',
        destructive: 'border-transparent bg-destructive text-destructive-foreground',
        outline: 'text-foreground',
        success:
          'border-transparent bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200',
        warning:
          'border-transparent bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200',
        danger: 'border-transparent bg-red-100 text-red-900 dark:bg-red-950 dark:text-red-200',
        info: 'border-transparent bg-sky-100 text-sky-900 dark:bg-sky-950 dark:text-sky-200',
        neutral: 'border-transparent bg-zinc-200 text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200',
        purple:
          'border-transparent bg-violet-100 text-violet-900 dark:bg-violet-950 dark:text-violet-200',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  },
);

function Badge({
  className,
  variant,
  asChild = false,
  ...props
}: React.ComponentProps<'span'> & VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot.Root : 'span';
  return (
    <Comp data-slot="badge" className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
export type BadgeVariant = NonNullable<VariantProps<typeof badgeVariants>['variant']>;
