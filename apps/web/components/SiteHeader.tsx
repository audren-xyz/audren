import Link from 'next/link'
import { ArrowRight, ArrowUpRight } from 'lucide-react'
import { AUDREN } from '@/lib/protocol'

export type NavSection = 'home' | 'compare' | 'developers' | 'how-it-works' | 'demo' | 'architecture' | 'faq' | 'privacy' | 'terms'

export function SiteHeader({ current = 'home' }: { current?: NavSection }) {
  return (
    <header className="site-header">
      <div className="container header-inner">
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

        <nav className="header-nav" aria-label="Primary navigation">
          <Link href="/how-it-works" aria-current={current === 'how-it-works' ? 'page' : undefined}>How it works</Link>
          <Link href="/compare" aria-current={current === 'compare' ? 'page' : undefined}>Compare</Link>
          <Link href="/developers" aria-current={current === 'developers' ? 'page' : undefined}>Developers</Link>
          <Link href="/faq" aria-current={current === 'faq' ? 'page' : undefined}>FAQ</Link>
        </nav>

        <div className="header-actions">
          <a
            className="header-ghost-link"
            href={AUDREN.githubCore}
            target="_blank"
            rel="noreferrer"
          >
            GitHub <ArrowUpRight size={13} />
          </a>
          <Link
            className={`header-demo-btn ${current === 'demo' ? 'is-active' : ''}`}
            href="/demo"
            aria-current={current === 'demo' ? 'page' : undefined}
          >
            Open App <ArrowRight size={14} />
          </Link>
        </div>
      </div>

      <nav className="mobile-subnav" aria-label="Mobile navigation">
        <div className="container mobile-subnav-inner">
          <Link href="/how-it-works" aria-current={current === 'how-it-works' ? 'page' : undefined}>How it works</Link>
          <Link href="/compare" aria-current={current === 'compare' ? 'page' : undefined}>Compare</Link>
          <Link href="/developers" aria-current={current === 'developers' ? 'page' : undefined}>Developers</Link>
          <Link href="/faq" aria-current={current === 'faq' ? 'page' : undefined}>FAQ</Link>
          <a href={AUDREN.githubCore} target="_blank" rel="noreferrer">
            GitHub <ArrowUpRight size={11} />
          </a>
        </div>
      </nav>
    </header>
  )
}
