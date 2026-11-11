import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";
import { themes as prismThemes } from "prism-react-renderer";

// Night Owl, with comments and deletions lifted to WCAG AA contrast on its navy background.
const darkCode = {
  ...prismThemes.nightOwl,
  styles: prismThemes.nightOwl.styles.map((entry) =>
    entry.types.includes("comment") ? { ...entry, style: { ...entry.style, color: "rgb(137, 160, 160)" } }
    : entry.types.includes("deleted") ? { ...entry, style: { ...entry.style, color: "rgb(239, 115, 112)" } }
    : entry)
};
import sourceLinks from "./plugins/remark-source-links.mjs";

// The Markdown stays in ../docs, so pages, generators and repository links keep their paths.
// URLs match the MkDocs site they replace: /Bower/<folder>/<page>/.
const config: Config = {
  title: "Bower",
  tagline: "Security telemetry, from source to proof.",
  favicon: "img/bower-mark.svg",
  url: "https://jusso-dev.github.io",
  baseUrl: "/Bower/",
  organizationName: "jusso-dev",
  projectName: "Bower",
  trailingSlash: true,
  onBrokenLinks: "throw",
  onBrokenAnchors: "throw",
  onDuplicateRoutes: "throw",
  future: { v4: { removeLegacyPostBuildHeadAttribute: true, useCssCascadeLayers: true }, faster: false },
  i18n: { defaultLocale: "en-AU", locales: ["en-AU"] },
  markdown: {
    // Plain .md files are read as CommonMark, not MDX: the library has shell snippets, KQL and
    // JSON with braces and angle brackets that MDX would try to evaluate.
    format: "detect",
    mermaid: true,
    hooks: { onBrokenMarkdownLinks: "throw", onBrokenMarkdownImages: "throw" }
  },
  plugins: ["./plugins/docs-files.mjs"],
  themes: [
    "@docusaurus/theme-mermaid",
    [
      // Local search: the index is built with the site and no query leaves the browser.
      "@easyops-cn/docusaurus-search-local",
      {
        hashed: true,
        language: ["en"],
        docsDir: "../docs",
        docsRouteBasePath: "/",
        indexBlog: false,
        indexPages: true,
        highlightSearchTermsOnTargetPage: true,
        searchResultLimits: 10,
        explicitSearchResultPath: true
      }
    ]
  ],
  presets: [
    [
      "classic",
      {
        docs: {
          path: "../docs",
          routeBasePath: "/",
          sidebarPath: "./sidebars.ts",
          editUrl: ({ docPath }) => `https://github.com/jusso-dev/Bower/edit/main/docs/${docPath}`,
          // The homepage is src/pages/index.tsx. research/ was excluded from the old site too.
          exclude: ["index.md", "research/**", "**/_*.md"],
          showLastUpdateTime: false,
          // Keep "01-syslog-delivery-reliability" in the URL, as on the MkDocs site.
          numberPrefixParser: false,
          beforeDefaultRemarkPlugins: [sourceLinks]
        },
        blog: false,
        theme: { customCss: "./src/css/custom.css" }
      } satisfies Preset.Options
    ]
  ],
  themeConfig: {
    image: "img/bower-readme-hero.png",
    colorMode: { defaultMode: "dark", respectPrefersColorScheme: true },
    docs: { sidebar: { hideable: true, autoCollapseCategories: true } },
    tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
    announcementBar: {
      id: "verified-delivery",
      content:
        'A collector accepting an event is not proof. <a href="/Bower/operations/evidence-bundles/">See how Bower proves arrival in Sentinel</a>.',
      isCloseable: true
    },
    navbar: {
      title: "Bower",
      // Empty alt: the logo sits beside the "Bower" title in the same link.
      logo: { alt: "", src: "img/bower-mark.svg" },
      hideOnScroll: false,
      items: [
        { type: "docSidebar", sidebarId: "startHere", position: "left", label: "Get started" },
        { type: "docSidebar", sidebarId: "guides", position: "left", label: "Guides" },
        { type: "docSidebar", sidebarId: "operations", position: "left", label: "Operations" },
        { type: "docSidebar", sidebarId: "productionReadiness", position: "left", label: "Production" },
        { type: "docSidebar", sidebarId: "security", position: "left", label: "Security" },
        { type: "docSidebar", sidebarId: "reference", position: "left", label: "Reference" },
        { to: "/guides/console-tour/", label: "Console tour", position: "left" },
        { href: "https://github.com/jusso-dev/Bower", position: "right", className: "header-github-link", "aria-label": "Bower on GitHub" }
      ]
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Start",
          items: [
            { label: "Your first verified event", to: "/getting-started/first-event/" },
            { label: "Choose a deployment", to: "/getting-started/deployment/" },
            { label: "Concepts", to: "/getting-started/concepts/" },
            { label: "FAQ", to: "/getting-started/faq/" }
          ]
        },
        {
          title: "Run it",
          items: [
            { label: "Installers", to: "/deployment/installers/" },
            { label: "Azure Monitor Agent", to: "/getting-started/azure-monitor-agent/" },
            { label: "AWS CloudWatch agent", to: "/getting-started/aws-cloudwatch-agent/" },
            { label: "Production readiness", to: "/production-readiness/" }
          ]
        },
        {
          title: "Reference",
          items: [
            { label: "bower CLI", to: "/reference/cli/" },
            { label: "BowerSecurity_CL columns", to: "/reference/sentinel-table/" },
            { label: "Architecture", to: "/architecture/overview/" },
            { label: "Threat model", to: "/security/threat-model/" }
          ]
        },
        {
          title: "Project",
          items: [
            { label: "GitHub", href: "https://github.com/jusso-dev/Bower" },
            { label: "Issues", href: "https://github.com/jusso-dev/Bower/issues" },
            { label: "Security policy", href: "https://github.com/jusso-dev/Bower/blob/main/SECURITY.md" },
            { label: "Licence (MIT)", href: "https://github.com/jusso-dev/Bower/blob/main/LICENSE" }
          ]
        }
      ],
      copyright: "Bower · Self-hosted security telemetry · MIT licence"
    },
    prism: {
      // Both pass WCAG AA contrast for every token colour (checked against their backgrounds).
      theme: prismThemes.vsLight,
      darkTheme: darkCode,
      additionalLanguages: ["bash", "powershell", "json", "yaml", "kusto", "ini", "docker", "csharp", "toml", "python", "diff"]
    },
    mermaid: { theme: { light: "neutral", dark: "dark" } }
  } satisfies Preset.ThemeConfig
};

export default config;
