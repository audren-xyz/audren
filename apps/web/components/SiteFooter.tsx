import Link from 'next/link'
import { ArrowUpRight } from 'lucide-react'
import { AUDREN, explorerAddress, shortHash, solscanAddress } from '@/lib/protocol'
import type { NavSection } from '@/components/SiteHeader'

export function SiteFooter({ current }: { current?: NavSection }) {
  return (
    <footer className="site-footer">
      <div className="container footer-grid">
        <div className="footer-brand-col">
          <Link className="brand-mark" href="/" aria-label="Audren home">
            <svg
              className="brand-glyph"
              viewBox="0 0 28 28"
              fill="none"
              aria-hidden="true"
            >
              <rect width="28" height="28" rx="2" fill="#121210" />
              <path d="M14 5.5L21 21.5H17.3L14 13.7L10.7 21.5H7L14 5.5Z" fill="#F4F1EA" />
              <rect x="11.5" y="19.2" width="5" height="2" fill="#C83E2B" />
            </svg>
            <span className="brand-name">Audren</span>
          </Link>
          <p className="footer-tagline">
            Private transfers, protocol-agnostic shielded DeFi, and selective receipts on Solana.
            Self-custodial, Apache-2.0 open source, pre-audit.
          </p>
          <a
            href={solscanAddress(AUDREN.programId, 'mainnet')}
            target="_blank"
            rel="noreferrer"
            className="footer-program-link mono"
          >
            {shortHash(AUDREN.programId, 10, 8)} <ArrowUpRight size={12} />
          </a>
        </div>

        <div className="footer-links-group">
          <h4>Product</h4>
          <Link href="/demo" aria-current={current === 'demo' ? 'page' : undefined}>
            Wallet &amp; Sandbox App
          </Link>
          <Link href="/#use-cases">Use Cases</Link>
          <Link href="/how-it-works">How It Works</Link>
          <Link href="/compare">Compare</Link>
        </div>

        <div className="footer-links-group">
          <h4>Developers</h4>
          <Link href="/developers">Start Building</Link>
          <Link href="/architecture" aria-current={current === 'architecture' ? 'page' : undefined}>
            Protocol Specification
          </Link>
          <a href={AUDREN.githubCore} target="_blank" rel="noreferrer">
            Protocol Source <ArrowUpRight size={12} />
          </a>
          <a href={AUDREN.githubExamples} target="_blank" rel="noreferrer">
            SDK Examples <ArrowUpRight size={12} />
          </a>
          <Link href="/faq" aria-current={current === 'faq' ? 'page' : undefined}>
            FAQ
          </Link>
        </div>

        <div className="footer-links-group">
          <h4>On-Chain Accounts</h4>
          <a href={explorerAddress(AUDREN.programId, 'verified-build')} target="_blank" rel="noreferrer">
            Verified Build ({AUDREN.releaseTag}) <ArrowUpRight size={12} />
          </a>
          <a href={explorerAddress(AUDREN.programId, 'idl')} target="_blank" rel="noreferrer">
            On-Chain Program IDL <ArrowUpRight size={12} />
          </a>
          <a href={explorerAddress(AUDREN.programId, 'security')} target="_blank" rel="noreferrer">
            Security Metadata <ArrowUpRight size={12} />
          </a>
          <a href={solscanAddress(AUDREN.pool0Pda, 'mainnet')} target="_blank" rel="noreferrer">
            Mainnet Pool #0 <ArrowUpRight size={12} />
          </a>
          <a href={solscanAddress(AUDREN.programId, 'devnet')} target="_blank" rel="noreferrer">
            Devnet Program <ArrowUpRight size={12} />
          </a>
        </div>

        <div className="footer-links-group">
          <h4>Legal</h4>
          <Link href="/privacy">Privacy</Link>
          <Link href="/terms">Terms</Link>
        </div>
      </div>

      <div className="container footer-bottom">
        <span>Audren Protocol · Apache-2.0</span>
        <span>Pre-audit · Upgradeable deployment</span>
      </div>
    </footer>
  )
}
