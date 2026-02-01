'use client';

import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface MarkdownContentProps {
  content: string;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="absolute top-2 right-2 p-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors opacity-0 group-hover:opacity-100 z-10"
      title="Copy code"
    >
      {copied ? (
        <Check className="h-4 w-4 text-emerald-400" />
      ) : (
        <Copy className="h-4 w-4 text-slate-400" />
      )}
    </button>
  );
}

export function MarkdownContent({ content }: MarkdownContentProps) {
  return (
    <div className="markdown-body text-slate-300 leading-relaxed">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => (
            <h1 className="text-3xl font-bold text-white mt-8 mb-4 pb-3 border-b border-slate-700">
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2 className="text-2xl font-bold text-white mt-8 mb-3">
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3 className="text-xl font-semibold text-white mt-6 mb-2">
              {children}
            </h3>
          ),
          h4: ({ children }) => (
            <h4 className="text-lg font-semibold text-white mt-4 mb-2">
              {children}
            </h4>
          ),
          h5: ({ children }) => (
            <h5 className="text-base font-semibold text-white mt-3 mb-1">
              {children}
            </h5>
          ),
          h6: ({ children }) => (
            <h6 className="text-sm font-semibold text-slate-200 mt-3 mb-1">
              {children}
            </h6>
          ),
          p: ({ children }) => (
            <p className="text-slate-300 leading-relaxed mb-4">
              {children}
            </p>
          ),
          a: ({ href, children }) => (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-violet-400 hover:text-violet-300 underline transition-colors"
            >
              {children}
            </a>
          ),
          strong: ({ children }) => (
            <strong className="font-semibold text-white">{children}</strong>
          ),
          em: ({ children }) => (
            <em className="italic text-slate-300">{children}</em>
          ),
          ul: ({ children }) => (
            <ul className="list-disc list-outside pl-6 my-4 space-y-1 text-slate-300">
              {children}
            </ul>
          ),
          ol: ({ children }) => (
            <ol className="list-decimal list-outside pl-6 my-4 space-y-1 text-slate-300">
              {children}
            </ol>
          ),
          li: ({ children }) => (
            <li className="text-slate-300 leading-relaxed">{children}</li>
          ),
          blockquote: ({ children }) => (
            <blockquote className="border-l-4 border-violet-500 pl-4 my-4 italic text-slate-400">
              {children}
            </blockquote>
          ),
          hr: () => <hr className="border-slate-700 my-8" />,
          code: ({ className, children, ...props }) => {
            const match = /language-(\w+)/.exec(className || '');
            const codeString = String(children).replace(/\n$/, '');
            
            // Check if this is inline code (no language class and short content)
            const isInline = !match && !codeString.includes('\n');
            
            if (isInline) {
              return (
                <code
                  className="px-1.5 py-0.5 bg-slate-800 text-emerald-400 rounded text-sm font-mono"
                  {...props}
                >
                  {children}
                </code>
              );
            }

            // Block code
            return (
              <code
                className={`block text-sm font-mono text-slate-300 ${className || ''}`}
                {...props}
              >
                {children}
              </code>
            );
          },
          pre: ({ children }) => {
            // Extract the code content for the copy button
            let codeContent = '';
            if (children && typeof children === 'object' && 'props' in children) {
              const childProps = children as React.ReactElement<{ children?: React.ReactNode }>;
              codeContent = String(childProps.props.children || '').replace(/\n$/, '');
            }
            
            return (
              <div className="relative group my-4">
                <CopyButton text={codeContent} />
                <pre className="bg-slate-800/80 rounded-xl p-4 overflow-x-auto">
                  {children}
                </pre>
              </div>
            );
          },
          table: ({ children }) => (
            <div className="overflow-x-auto my-6">
              <table className="min-w-full border-collapse">
                {children}
              </table>
            </div>
          ),
          thead: ({ children }) => (
            <thead className="bg-slate-800/50">
              {children}
            </thead>
          ),
          tbody: ({ children }) => (
            <tbody className="divide-y divide-slate-800">
              {children}
            </tbody>
          ),
          tr: ({ children }) => (
            <tr className="hover:bg-slate-800/30 transition-colors">
              {children}
            </tr>
          ),
          th: ({ children }) => (
            <th className="text-left text-white font-semibold py-3 px-4 border-b border-slate-700">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="text-slate-300 py-3 px-4 border-b border-slate-800">
              {children}
            </td>
          ),
          img: ({ src, alt }) => (
            <img
              src={src}
              alt={alt || ''}
              className="rounded-lg my-4 max-w-full h-auto"
            />
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
