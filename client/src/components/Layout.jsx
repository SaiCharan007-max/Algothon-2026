import { Link, Outlet } from 'react-router-dom'
import { Code2 } from 'lucide-react'

export default function Layout() {
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-line bg-bg/80 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4">
          <Link to="/" className="flex items-center gap-2.5">
            <img src="/favicon.svg" alt="" className="h-7 w-7" />
            <span className="text-[15px] font-semibold tracking-tight text-white">LogHound</span>
            <span className="hidden text-xs text-muted sm:inline">· find the intruder</span>
          </Link>
          <nav className="flex items-center gap-4 text-sm text-muted">
            <Link to="/" className="hover:text-white">
              Analyses
            </Link>
            <a href="https://github.com/SaiCharan007-max/Algothon-2026" target="_blank" rel="noreferrer" className="hover:text-white" title="Source code">
              <Code2 className="h-4 w-4" />
            </a>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-8">
        <Outlet />
      </main>
    </div>
  )
}
