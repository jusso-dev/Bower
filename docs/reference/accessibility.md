# Accessibility

The documentation is designed for keyboard use, narrow screens and light or dark
appearance. Text remains available without animation or JavaScript. The navigation and
search come from Docusaurus. The site follows your system appearance, opening in dark
navy when there is none; the header control cycles light, dark and system, and your
choice is remembered across pages. Every console screenshot exists in both appearances.

## Motion and keyboard controls

- The homepage has no animation. If your device requests reduced motion, hover transitions are turned off too.
- Use Tab to move through links and controls. Focus is visibly outlined.
- The console gallery on the homepage is a set of tabs: use the arrow keys, Home and End to change view.
- Links inside running text are underlined, so they do not rely on colour alone.
- Use the skip link to move past repeated navigation. Search opens with Ctrl+K or Cmd+K.
- Browser tests run axe's default rules on 17 pages in both appearances, and check that
  the homepage and guides fit a 320 px screen.

## Management console

The console follows your system light or dark preference, and the **Dark mode** /
**Light mode** control in the side rail overrides it; the choice is remembered. Pages
reflow to a single column at narrow widths, and tables become stacked cards, so nothing
scrolls sideways at 320 px.

Every console route is checked automatically in light and dark mode, on desktop and a
mobile viewport, with axe-core against the WCAG 2.0, 2.1 and 2.2 A and AA rules; the
build fails on any serious or critical finding. The same checks run at 320 px, and a
keyboard-only test tabs into the setup wizard, checks every control shows a focus
indicator and operates the first step with Enter. Setup and source steps are named from
their visible text (for example "Step 1: Sign in Done"), so voice control can select
what you can see.

## Checks and limits

The documentation site build checks internal links and anchors. Browser checks cover keyboard
interaction, reduced motion, local search and narrow layouts. Automated axe checks
help find accessibility defects; they do not establish WCAG conformance by themselves.
A full manual assistive-technology and non-technical-user evaluation remains to be
completed. We do not claim a WCAG certification.

If a page is difficult to use, [open an issue](https://github.com/jusso-dev/Bower/issues/new)
with the page address, the task you were trying to complete, and your browser or
assistive technology. Do not include secrets, tenant identifiers or event payloads.
