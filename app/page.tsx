import { EcosystemStrip, Hero, HowItWorks, SiteFooter, SiteHeader } from "@/components/skill-guard/page-sections"
import { SkillScanner } from "@/components/skill-guard/skill-scanner"
import { ThreatIntelligence } from "@/components/skill-guard/threat-intelligence"

export default function Page() {
  return (
    <>
      <a href="#analyzer" className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-50 focus:rounded-lg focus:bg-primary focus:px-4 focus:py-3 focus:text-primary-foreground">Skip to skill analyzer</a>
      <SiteHeader />
      <main>
        <Hero />
        <SkillScanner />
        <div className="content-shell"><EcosystemStrip /></div>
        <HowItWorks />
        <ThreatIntelligence />
      </main>
      <SiteFooter />
    </>
  )
}
