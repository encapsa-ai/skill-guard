"use client"

import { ArrowUpRight, BookOpen, FileSearch, Fingerprint, Info, ShieldAlert } from "lucide-react"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { CATEGORIES } from "@/lib/skill-guard/types"
import { RESEARCH_REVIEWED_ON, RESEARCH_SOURCES, THREAT_RESEARCH } from "@/lib/skill-guard/research"

export function ThreatIntelligence() {
  return (
    <section id="threat-intelligence" className="research-section" aria-labelledby="research-title">
      <div className="content-shell">
        <div className="flex flex-col gap-7">
          <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
            <div className="flex flex-col gap-3">
              <p className="hero-eyebrow text-muted-foreground">BUILT ON REAL-WORLD THREAT RESEARCH</p>
              <h2 id="research-title" className="section-heading text-balance">More than a suspicious line of code.</h2>
              <p className="max-w-2xl text-base leading-relaxed text-muted-foreground">Understand the attack surface—and exactly where automated analysis stops.</p>
            </div>
            <Badge variant="outline">8 threat categories</Badge>
          </div>
          <Tabs defaultValue="coverage" className="gap-6">
            <TabsList variant="line" className="max-w-full flex-wrap justify-start gap-4 group-data-horizontal/tabs:h-auto [&>[role=tab]]:h-9">
              <TabsTrigger value="coverage"><ShieldAlert data-icon="inline-start" />What we look for</TabsTrigger>
              <TabsTrigger value="sources"><BookOpen data-icon="inline-start" />Research & sources</TabsTrigger>
              <TabsTrigger value="scope"><FileSearch data-icon="inline-start" />Scan limitations</TabsTrigger>
            </TabsList>
            <TabsContent value="coverage">
              <Accordion className="grid items-start gap-x-10 md:grid-cols-2" multiple>
                {THREAT_RESEARCH.map((threat) => (
                  <AccordionItem key={threat.category} value={threat.category}>
                    <AccordionTrigger className="py-5">
                      <span className="flex flex-col gap-1">
                        <span className="font-semibold">{CATEGORIES[threat.category]}</span>
                        <span className="text-sm font-normal text-muted-foreground">{threat.summary}</span>
                      </span>
                    </AccordionTrigger>
                    <AccordionContent>
                      <div className="flex flex-col gap-4 pb-4 text-sm leading-relaxed text-muted-foreground">
                        <p><strong className="text-foreground">Where it hides. </strong>{threat.files}</p>
                        <p><strong className="text-foreground">Observed techniques. </strong>{threat.techniques}</p>
                        <p><strong className="text-foreground">Our coverage. </strong>{threat.coverage}</p>
                        <p><strong className="text-foreground">Your defense. </strong>{threat.defense}</p>
                        <div className="flex flex-wrap items-center gap-3">
                          {RESEARCH_SOURCES.filter((source) => threat.sourceIds.includes(source.id)).map((source) => (
                            <a key={source.id} href={source.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-foreground">{source.publisher}<ArrowUpRight className="size-3.5" /></a>
                          ))}
                        </div>
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </TabsContent>
            <TabsContent value="sources">
              <div className="flex flex-col gap-5">
                <p className="text-sm text-muted-foreground">Research reviewed {RESEARCH_REVIEWED_ON}. These sources inform Skill Guard&apos;s rules; we do not run or claim certification from these vendors&apos; scanners.</p>
                <div className="grid gap-4 md:grid-cols-2">
                  {RESEARCH_SOURCES.map((source) => (
                    <article key={source.id} className="source-card">
                      <div className="flex flex-col gap-3">
                        <span className="font-mono text-sm text-muted-foreground">{source.publisher}</span>
                        <h3 className="text-base font-semibold"><a className="inline-flex items-start gap-2 hover:underline" href={source.url} target="_blank" rel="noopener noreferrer">{source.title}<ArrowUpRight className="size-4 shrink-0" /></a></h3>
                        <p className="text-sm leading-relaxed text-muted-foreground">{source.detail}</p>
                      </div>
                    </article>
                  ))}
                </div>
              </div>
            </TabsContent>
            <TabsContent value="scope">
              <div className="flex flex-col gap-5">
                <Alert><Info /><AlertTitle>A security check, not a security certificate.</AlertTitle><AlertDescription>No findings does not mean no risk. Skill Guard is a best-effort, heuristic static analyzer with optional AI-assisted review. It can produce false positives and miss threats.</AlertDescription></Alert>
                <div className="grid gap-6 text-sm leading-relaxed md:grid-cols-2">
                  <div className="flex flex-col gap-3"><h3 className="text-base font-semibold">What happens in a scan</h3><p className="text-muted-foreground">Every accepted archive entry is inventoried and hashed. Decodable text is checked across the full file, including Markdown, Python, shell, JavaScript, PowerShell, configuration, and extensionless files. Common encoded literals receive a bounded decoding pass.</p><p className="text-muted-foreground">ZIP paths, sizes, entry types, expansion ratios, and checksums are validated. Archives above 20 MB expanded, files above 2 MB, more than 500 entries, unsafe paths, symlinks, duplicates, and encryption are rejected.</p></div>
                  <div className="flex flex-col gap-3"><h3 className="text-base font-semibold">What remains outside the scan</h3><p className="text-muted-foreground">No execution, sandbox detonation, full AST/dataflow analysis, decompilation, OCR, registry reputation, CVE lookup, signature verification, or transitive dependency resolution. Nested archives and opaque assets are flagged as uninspected. Remote URLs and dependencies are never downloaded.</p><p className="text-muted-foreground">AI review is advisory and bounded to 80,000 source characters. Any omitted files are disclosed. Only findings with evidence matched to a supplied file and line are accepted; the AI cannot erase static findings.</p></div>
                </div>
              </div>
            </TabsContent>
          </Tabs>
          <div id="privacy" className="border-t border-border pt-6">
            <div className="flex items-start gap-3">
              <Fingerprint className="mt-1 size-5 shrink-0 text-muted-foreground" aria-hidden="true" />
              <p className="text-sm leading-relaxed text-muted-foreground"><strong className="font-medium text-foreground">Your skills stay yours.</strong> Skill Guard processes uploads in server memory and does not save archives or reports. Reports remain in this page until you leave or clear them; download a copy to keep it. Optional AI review sends best-effort redacted text to an AI provider through Vercel AI Gateway, where provider retention policies apply. Remove secrets before uploading. Always pair automated analysis with human review and least-privilege access.</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
