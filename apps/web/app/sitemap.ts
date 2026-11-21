import type { MetadataRoute } from 'next'
export const dynamic = 'force-static'
export default function sitemap(): MetadataRoute.Sitemap {
  return ['', 'demo/', 'how-it-works/', 'compare/', 'developers/', 'architecture/', 'faq/', 'privacy/', 'terms/'].map(path => ({ url: `https://audren.xyz/${path}` }))
}
