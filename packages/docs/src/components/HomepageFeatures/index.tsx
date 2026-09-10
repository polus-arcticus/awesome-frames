import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

// Small inline icons, in the same "frame corners" family as the site logo.
// Inline (not <img>) so they inherit color via currentColor in both themes.

function FrameIcon() {
  return (
    <svg viewBox="0 0 40 40" width="36" height="36" role="img" aria-hidden="true">
      <g fill="none" stroke="currentColor" strokeWidth="3.4" strokeLinecap="round" strokeLinejoin="round">
        <path d="M4 14 V4 H14" />
        <path d="M26 4 H36 V14" />
        <path d="M36 26 V36 H26" />
        <path d="M14 36 H4 V26" />
      </g>
      <circle cx="20" cy="20" r="3.6" fill="currentColor" />
    </svg>
  );
}

function KeyIcon() {
  return (
    <svg viewBox="0 0 40 40" width="36" height="36" role="img" aria-hidden="true">
      <g fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="13" cy="13" r="7" />
        <path d="M18 18 L32 32" />
        <path d="M25 25 L29 21" />
        <path d="M29 29 L33 25" />
      </g>
      <circle cx="13" cy="13" r="1.8" fill="currentColor" stroke="none" />
    </svg>
  );
}

function BookIcon() {
  return (
    <svg viewBox="0 0 40 40" width="36" height="36" role="img" aria-hidden="true">
      <g fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
        <rect x="7" y="8" width="26" height="26" rx="2" />
        <path d="M20 8 V34" />
        <path d="M11 15 H17" />
        <path d="M11 21 H17" />
        <path d="M23 15 H29" />
        <path d="M23 21 H29" />
      </g>
    </svg>
  );
}

type FeatureItem = {
  title: string;
  to: string;
  Icon: () => ReactNode;
  description: ReactNode;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'EIP-8141 Frame transactions',
    to: '/docs/eip-8141',
    Icon: FrameIcon,
    description: (
      <>
        A new transaction type built from <code>VERIFY</code>/<code>SENDER</code> frames
        — the account-abstraction primitive: any signature scheme you can
        implement in EVM opcodes authorizes the transaction.
      </>
    ),
  },
  {
    title: 'Real recipes, not just theory',
    to: '/docs/recipes',
    Icon: KeyIcon,
    description: (
      <>
        A self-verifying Frame account authorized by a BIP-340/Nostr Schnorr
        signature — the same secp256k1 key that signs a Nostr event
        authorizes a Frame transaction directly, deployed and exercised
        against a live testnet.
      </>
    ),
  },
  {
    title: 'The grimoire',
    to: '/docs/grimoire',
    Icon: BookIcon,
    description: (
      <>
        A separate, deliberately-insecure track: classic asymmetric
        cryptography implemented directly in raw Yul, small and toy enough
        to verify by hand — including wallets sized to be crackable on
        purpose, in a chosen window of time.
      </>
    ),
  },
];

function Feature({title, to, Icon, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className={clsx('padding-horiz--md', styles.feature)}>
        <div className={styles.featureIcon}>
          <Icon />
        </div>
        <Heading as="h3">
          <Link to={to}>{title}</Link>
        </Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
