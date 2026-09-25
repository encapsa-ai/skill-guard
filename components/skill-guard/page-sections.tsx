import Image from "next/image"
import { ArrowUpRight, FileCheck2, Fingerprint, FolderArchive, ScanLine, ShieldCheck } from "lucide-react"
import { buttonVariants } from "@/components/ui/button"
import { cn } from "@/lib/utils"

const logo = "https://hebbkx1anhila5yf.public.blob.vercel-storage.com/logo-primary-SqdwV8eBj6mgl5QcX6ETuTszAuHCrJ.png"

export function SiteHeader() {
  return (
    <header className="site-header">
      <div className="content-shell header-inner flex items-center justify-between">
        <a href="#" className="flex items-center gap-4" aria-label="Skill Guard by Encapsa home">
          <Image src={logo} width={135} height={30} alt="Encapsa" priority className="h-auto w-28 sm:w-32" />
          <span className="h-6 w-px bg-border" aria-hidden="true" />
          <span className="text-base font-semibold tracking-tight sm:text-lg">Skill Guard<span className="text-gold">.</span></span>
        </a>
        <nav aria-label="Main navigation" className="flex items-center gap-8">
          <a className="hidden text-sm font-medium text-muted-foreground transition-colors hover:text-foreground md:block" href="#how-it-works">How it works</a>
          <a className="hidden text-sm font-medium text-muted-foreground transition-colors hover:text-foreground md:block" href="#threat-intelligence">What we detect</a>
          <a href="https://encapsa.ai" target="_blank" rel="noopener noreferrer" className={cn(buttonVariants({ variant: "outline", size: "sm" }), "hidden sm:inline-flex")}>
            Meet Encapsa <ArrowUpRight data-icon="inline-end" />
          </a>
        </nav>
      </div>
    </header>
  )
}

export function Hero() {
  return (
    <section className="hero content-shell reveal text-center" aria-labelledby="page-title">
      <div className="flex flex-col items-center gap-5">
        <div className="hero-eyebrow flex items-center gap-2 text-muted-foreground">
          <ShieldCheck className="size-4 text-gold-foreground" aria-hidden="true" />
          <span>AI SKILL SECURITY ANALYZER</span>
        </div>
        <h1 id="page-title" className="hero-heading text-balance">
          Powerful skills. <span className="hero-accent">Safer agents.</span>
        </h1>
        <p className="max-w-2xl text-pretty text-base leading-relaxed text-muted-foreground sm:text-lg">
          Your AI skills can do a lot. Make sure it&apos;s what you intended.{" "}<br className="hidden sm:block" />
          Uncover hidden threats before you give them access.
        </p>
      </div>
    </section>
  )
}

export function EcosystemStrip() {
  return (
    <div className="ecosystem-strip flex flex-col items-center gap-5 text-center">
      <p className="text-sm text-muted-foreground">Built for the open Agent Skills ecosystem</p>
      <div className="flex flex-wrap items-center justify-center gap-x-9 gap-y-4 text-base font-semibold text-foreground/75 sm:gap-x-12">
        <span className="flex items-center gap-2"><span className="font-mono text-lg text-gold-foreground" aria-hidden="true">*</span>Claude Code</span>
        <span className="font-mono tracking-tight">OpenClaw</span>
        <span className="tracking-tight">Cursor</span>
        <span className="font-mono tracking-tight">Codex</span>
        <span className="text-sm font-normal text-muted-foreground">+ any SKILL.md package</span>
      </div>
    </div>
  )
}

const steps = [
  { icon: FolderArchive, title: "Drop in your skills", description: "Upload one ZIP or a whole toolkit. We unpack it in memory—not on a live filesystem." },
  { icon: ScanLine, title: "Look beneath the surface", description: "Inspect instructions, scripts, and supporting text for risky patterns. Add AI review for more context." },
  { icon: FileCheck2, title: "Make an informed call", description: "See what was found, where it lives, and what to do next. Download a report you can share." },
]

export function HowItWorks() {
  return (
    <section id="how-it-works" className="methodology-section" aria-labelledby="methodology-title">
      <div className="content-shell">
        <div className="flex flex-col items-center gap-3 text-center">
          <p className="hero-eyebrow text-muted-foreground">LESS GUESSWORK. MORE CONFIDENCE.</p>
          <h2 id="methodology-title" className="section-heading text-balance">From unknown to understood.</h2>
        </div>
        <div className="mt-7 grid md:grid-cols-3">
          {steps.map(({ icon: Icon, title, description }, index) => (
            <article key={title} className="method-card border-b last:border-0 md:border-r md:border-b-0">
              <div className="flex flex-col gap-4">
                <div className="flex items-center gap-3">
                  <Icon className="size-6 text-gold-foreground" strokeWidth={1.5} aria-hidden="true" />
                  <span className="font-mono text-sm text-muted-foreground">0{index + 1}</span>
                </div>
                <h3 className="text-lg font-semibold tracking-tight">{title}</h3>
                <p className="text-sm leading-relaxed text-muted-foreground">{description}</p>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  )
}

export function SiteFooter() {
  return (
    <footer className="site-footer content-shell">
      <div className="flex flex-col items-center justify-between gap-5 sm:flex-row">
        <div className="flex items-center gap-3">
          <Image src="https://hebbkx1anhila5yf.public.blob.vercel-storage.com/favicon-QiRNvQDsBUTWWHZquxaLK8gzhkWw5g.png" width={28} height={28} alt="" />
          <p className="text-sm text-muted-foreground">An <a className="font-semibold text-foreground hover:underline" href="https://encapsa.ai" target="_blank" rel="noopener noreferrer">Encapsa</a> tool. Built for a more trusted AI world.</p>
        </div>
        <div className="flex items-center gap-5 text-sm text-muted-foreground">
          <a className="flex items-center gap-1.5 hover:text-foreground" href="#privacy"><Fingerprint className="size-4" aria-hidden="true" />Privacy & scope</a>
          <span>© {new Date().getFullYear()} Encapsa</span>
        </div>
      </div>
    </footer>
  )
}
