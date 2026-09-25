import { createSampleArchive } from "@/lib/skill-guard/sample"

export const runtime = "nodejs"

export function GET() {
  return new Response(new Uint8Array(createSampleArchive()), {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": 'attachment; filename="calendar-helper-demo.zip"',
      "Cache-Control": "public, max-age=3600",
    },
  })
}
