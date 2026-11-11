'use client';

import { useTheme } from 'next-themes';
import { Toaster as Sonner, type ToasterProps } from 'sonner';

// Sonner's light rich colours fall below WCAG AA on their tinted backgrounds (3.1:1 to 4.4:1);
// these darker text shades of the same hues reach at least 4.8:1. The dark palette already passes.
const LIGHT_RICH_TEXT = {
  '--success-text': 'hsl(140, 100%, 25%)',
  '--info-text': 'hsl(210, 92%, 42%)',
  '--warning-text': 'hsl(31, 92%, 34%)',
  '--error-text': 'hsl(360, 100%, 42%)',
};

/** Toasts announce through a polite live region (sonner renders `aria-live` and `role="status"`). */
function Toaster(props: ToasterProps) {
  const { theme = 'system', resolvedTheme } = useTheme();
  return (
    <Sonner
      theme={theme as ToasterProps['theme']}
      className="toaster group"
      closeButton
      richColors
      style={
        {
          '--normal-bg': 'var(--popover)',
          '--normal-text': 'var(--popover-foreground)',
          '--normal-border': 'var(--border)',
          ...(resolvedTheme === 'dark' ? {} : LIGHT_RICH_TEXT),
        } as React.CSSProperties
      }
      {...props}
    />
  );
}

export { Toaster };
