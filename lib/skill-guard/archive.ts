import { createHash } from "node:crypto"
import { fromBufferPromise, type Entry } from "yauzl"
import { MAX_ENTRIES, MAX_EXPANDED_BYTES, MAX_FILE_BYTES, MAX_ZIP_BYTES, type FileInventory } from "./types"

export class ArchiveError extends Error {
  constructor(message: string, public status = 400) {
    super(message)
    this.name = "ArchiveError"
  }
}

export interface ArchiveFile extends Omit<FileInventory, "findings"> {
  content: string | null
}

export interface InspectedArchive {
  files: ArchiveFile[]
  expandedBytes: number
  sha256: string
}

const crcTable = Uint32Array.from({ length: 256 }, (_, index) => {
  let value = index
  for (let bit = 0; bit < 8; bit++) value = (value & 1) ? 0xedb88320 ^ (value >>> 1) : value >>> 1
  return value >>> 0
})

function checksum(bytes: Buffer) {
  let crc = 0xffffffff
  for (const byte of bytes) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

function validateEntry(entry: Entry, seen: Map<string, "file" | "directory">) {
  const path = entry.fileName
  const normalized = path.normalize("NFKC").replace(/\/$/, "").toLowerCase()
  if (!path || path.length > 300 || /[\x00-\x1f\x7f\\]/.test(path) || path.startsWith("/") || /^[a-z]:/i.test(path) || normalized.split("/").some((part) => part === ".." || part === "." || !part)) {
    throw new ArchiveError("The ZIP contains unsafe or ambiguous paths. Repack it using relative paths without traversal or control characters.")
  }
  if (seen.has(normalized)) throw new ArchiveError("The ZIP contains duplicate or case-conflicting paths. Each file and directory must have a unique path.")
  const directory = path.endsWith("/")
  const parents = normalized.split("/")
  parents.pop()
  while (parents.length) {
    if (seen.get(parents.join("/")) === "file") throw new ArchiveError("A ZIP path is used as both a file and a directory.")
    parents.pop()
  }
  if (!directory && [...seen.keys()].some((other) => other.startsWith(`${normalized}/`))) throw new ArchiveError("A ZIP path is used as both a file and a directory.")
  seen.set(normalized, directory ? "directory" : "file")
  const mode = (entry.externalFileAttributes >>> 16) & 0xf000
  if (mode !== 0 && mode !== 0x8000 && mode !== 0x4000) {
    throw new ArchiveError("The ZIP contains a symlink or special file. Only regular files and directories are accepted.")
  }
  if (mode === 0x4000 && !path.endsWith("/")) throw new ArchiveError("The ZIP has inconsistent directory metadata.")
  if (entry.isEncrypted()) throw new ArchiveError("Encrypted ZIP entries cannot be inspected. Upload an unencrypted archive without passwords.")
  if (!entry.canDecodeFileData()) throw new ArchiveError("This ZIP uses an unsupported compression method. Repack it using standard ZIP compression.")
  if (!Number.isSafeInteger(entry.uncompressedSize) || !Number.isSafeInteger(entry.compressedSize) || entry.uncompressedSize < 0 || entry.compressedSize < 0) {
    throw new ArchiveError("The ZIP has invalid file-size metadata.")
  }
  if (entry.uncompressedSize > MAX_FILE_BYTES) throw new ArchiveError("A file inside this ZIP exceeds the 2 MB inspection limit. Split or remove large assets, then scan again.", 413)
  if (entry.uncompressedSize > 1024 * 1024 && entry.uncompressedSize / Math.max(1, entry.compressedSize) > 200) {
    throw new ArchiveError("This ZIP has an excessive decompression ratio and was rejected to prevent archive-bomb attacks.", 413)
  }
}

function describeContent(path: string, data: Buffer): { kind: FileInventory["kind"]; content: string | null } {
  const magic = data.subarray(0, 8).toString("hex")
  if (/\.(?:zip|7z|rar|tar|tgz|gz|bz2|xz|whl|jar|docx|xlsx|pptx)$/i.test(path) || magic.startsWith("504b0304") || magic.startsWith("504b0506") || magic.startsWith("1f8b") || magic.startsWith("377abcaf271c") || magic.startsWith("52617221") || data.subarray(257, 262).toString() === "ustar") {
    return { kind: "archive", content: null }
  }
  if (/\.(?:exe|dll|so|dylib|pyc|pyo|wasm|class)$/i.test(path) || /^(?:4d5a|7f454c46|cffaedfe|cefaedfe|feedface|feedfacf|cafebabe|0061736d)/.test(magic)) {
    return { kind: "executable", content: null }
  }
  if (/^(?:89504e47|ffd8ff|47494638|25504446|52494646)/.test(magic)) return { kind: "binary", content: null }
  try {
    const encoding = magic.startsWith("fffe") ? "utf-16le" : magic.startsWith("feff") ? "utf-16be" : "utf-8"
    const content = new TextDecoder(encoding, { fatal: true }).decode(data)
    if (content.includes("\0")) return { kind: "binary", content: null }
    const controls = content.match(/[\x01-\x08\x0b\x0c\x0e-\x1f]/g)?.length ?? 0
    if (controls > Math.max(2, content.length * 0.01)) return { kind: "binary", content: null }
    return { kind: "text", content }
  } catch {
    return { kind: "binary", content: null }
  }
}

export async function inspectArchive(buffer: Buffer, signal?: AbortSignal): Promise<InspectedArchive> {
  if (buffer.length > MAX_ZIP_BYTES) throw new ArchiveError("The maximum ZIP size is 4 MB.", 413)
  if (buffer.length < 22 || buffer[0] !== 0x50 || buffer[1] !== 0x4b) throw new ArchiveError("This file is not a valid ZIP archive. Renaming a file to .zip does not convert it.")
  let zip
  try {
    zip = await fromBufferPromise(buffer, { strictFileNames: true, validateEntrySizes: true, decodeStrings: true })
  } catch {
    throw new ArchiveError("The ZIP directory is damaged or invalid. Re-create the archive and try again.")
  }
  const started = Date.now()
  const files: ArchiveFile[] = []
  const paths = new Map<string, "file" | "directory">()
  const ranges: { start: number; end: number }[] = []
  let expandedBytes = 0
  let entries = 0
  function checkBudget() {
    if (signal?.aborted) throw new ArchiveError("The scan was cancelled.", 499)
    if (Date.now() - started > 10_000) throw new ArchiveError("Archive inspection exceeded its safety time budget. Try a smaller archive.", 413)
  }
  try {
    if (zip.entryCount > MAX_ENTRIES) throw new ArchiveError("This archive has more than 500 entries. Split it into smaller skill archives.", 413)
    for await (const entry of zip.eachEntry()) {
      checkBudget()
      if (++entries > MAX_ENTRIES) throw new ArchiveError("The archive entry limit was exceeded.", 413)
      validateEntry(entry, paths)
      if (entry.fileName.endsWith("/")) {
        if (entry.uncompressedSize !== 0) throw new ArchiveError("A directory entry contains unexpected file data.")
        continue
      }
      if (expandedBytes + entry.uncompressedSize > MAX_EXPANDED_BYTES) throw new ArchiveError("This archive expands beyond the 20 MB safety limit.", 413)
      const header = await zip.readLocalFileHeaderPromise(entry)
      if (!header.fileName.equals(entry.fileNameRaw) || header.compressionMethod !== entry.compressionMethod || (header.generalPurposeBitFlag & 1) !== (entry.generalPurposeBitFlag & 1)) {
        throw new ArchiveError("Local and central ZIP records disagree. The archive may be malformed or tampered with.")
      }
      const range = { start: entry.relativeOffsetOfLocalHeader, end: header.fileDataStart + entry.compressedSize }
      if (range.start < 0 || range.end > buffer.length || ranges.some((other) => range.start < other.end && range.end > other.start)) {
        throw new ArchiveError("The ZIP contains overlapping or out-of-bounds entries.")
      }
      ranges.push(range)
      const stream = await zip.openReadStreamPromise(entry)
      const chunks: Buffer[] = []
      let size = 0
      const abort = () => stream.destroy(new ArchiveError("The scan was cancelled.", 499))
      signal?.addEventListener("abort", abort, { once: true })
      try {
        for await (const chunk of stream) {
          checkBudget()
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
          size += bytes.length
          expandedBytes += bytes.length
          if (size > MAX_FILE_BYTES || size > entry.uncompressedSize || expandedBytes > MAX_EXPANDED_BYTES) {
            throw new ArchiveError("The ZIP expanded beyond its declared size or the inspection safety limits.", 413)
          }
          chunks.push(bytes)
        }
      } finally {
        signal?.removeEventListener("abort", abort)
        stream.destroy()
      }
      const data = Buffer.concat(chunks, size)
      if (size !== entry.uncompressedSize || checksum(data) !== entry.crc32) throw new ArchiveError("A file failed its ZIP integrity check. Re-create the archive before scanning.")
      const { kind, content } = describeContent(entry.fileName, data)
      files.push({
        path: entry.fileName,
        bytes: size,
        sha256: createHash("sha256").update(data).digest("hex"),
        kind,
        content,
        status: content === null ? "not-inspected" : "inspected",
      })
    }
    if (!files.length) throw new ArchiveError("This ZIP has no files to inspect. Include your SKILL.md and supporting files.")
    return { files, expandedBytes, sha256: createHash("sha256").update(buffer).digest("hex") }
  } catch (cause) {
    if (cause instanceof ArchiveError) throw cause
    throw new ArchiveError("The ZIP could not be safely decoded. Check for unsafe paths, corruption, or unsupported compression.")
  } finally {
    zip.close()
  }
}
