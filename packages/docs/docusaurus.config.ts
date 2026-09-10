import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const GITHUB_URL = 'https://github.com/polus-arcticus/awesome-frames';

const config: Config = {
  title: 'awesome-frames',
  tagline: 'A playground for EIP-8141 Frame transactions on Ethereum',
  favicon: 'img/favicon.svg',

  // Future flags, see https://docusaurus.io/docs/api/docusaurus-config#future
  future: {
    v4: true, // Improve compatibility with the upcoming Docusaurus v4
  },

  // GitHub Pages deployment target.
  url: 'https://polus-arcticus.github.io',
  baseUrl: '/awesome-frames/',
  organizationName: 'polus-arcticus',
  projectName: 'awesome-frames',
  deploymentBranch: 'gh-pages',

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: `${GITHUB_URL}/tree/main/packages/docs/`,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'awesome-frames',
      logo: {
        alt: 'awesome-frames logo',
        src: 'img/logo.svg',
        srcDark: 'img/logo-dark.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          href: GITHUB_URL,
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Introduction', to: '/docs/intro'},
            {label: 'EIP-8141 primer', to: '/docs/eip-8141'},
            {label: 'The grimoire', to: '/docs/grimoire'},
          ],
        },
        {
          title: 'The testnet',
          items: [
            {label: 'ethrex explorer', href: 'https://dora.privacy.ethrex.xyz'},
            {label: 'Faucet', href: 'https://faucet.privacy.ethrex.xyz/artifacts'},
          ],
        },
        {
          title: 'More',
          items: [
            {label: 'GitHub', href: GITHUB_URL},
            {label: 'EIP-8141 text', href: 'https://eips.ethereum.org/EIPS/eip-8141'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} awesome-frames contributors. MIT Licensed. Research/prototype tooling for a Draft EIP — see the status note on the homepage.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
