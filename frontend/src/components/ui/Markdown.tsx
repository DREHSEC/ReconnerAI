import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import remarkBreaks from 'remark-breaks'
import type { Components } from 'react-markdown'
import { cn } from '../../lib/utils'

const SAFE = /^(https?:|mailto:)/i

function safeUrl(url: string): string {
  return SAFE.test(url) ? url : ''
}

const components: Components = {
  a: ({ href, children }) => (
    <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
  ),
  // Don't fetch remote images from model output; show a link instead.
  img: ({ alt, src }) => {
    const label = alt || src || 'image'
    if (src && SAFE.test(src)) {
      return <a href={src} target="_blank" rel="noopener noreferrer">{label}</a>
    }
    return <span>{label}</span>
  },
  table: ({ children }) => (
    <div className="md-table"><table>{children}</table></div>
  ),
}

export function Markdown({ children, className }: { children: string; className?: string }) {
  const text = children ?? ''
  if (!text.trim()) return null
  return (
    <div className={cn('md', className)}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm, remarkBreaks]}
        urlTransform={safeUrl}
        components={components}
      >
        {text}
      </ReactMarkdown>
    </div>
  )
}
