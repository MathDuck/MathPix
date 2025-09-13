let __pako: any = null;
async function getPako() {
    if (__pako) return __pako;
    try {
        // @ts-ignore - dynamic
        __pako = await import('pako');
        return __pako;
    } catch {
        return null;
    }
}

export interface OptimizeResult {
    data: ArrayBuffer;
    originalBytes: number;
    optimizedBytes: number;
    changed: boolean;
    note?: string;
    format: string;
}

let __crcTable: number[] | null = null;
function crc32(buf: Uint8Array): number {
    if (!__crcTable) {
        __crcTable = [];
        for (let n = 0; n < 256; n++) {
            let c = n;
            for (let k = 0; k < 8; k++) c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
            __crcTable[n] = c >>> 0;
        }
    }
    let crc = 0 ^ -1;
    for (let i = 0; i < buf.length; i++) crc = (__crcTable[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8)) >>> 0;
    return (crc ^ -1) >>> 0;
}

async function optimizePNG(input: Uint8Array): Promise<OptimizeResult | null> {
    if (input.length < 8) return null;
    const sig = input.subarray(0, 8);
    const PNG_SIG = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
    for (let k = 0; k < 8; k++) if (sig[k] !== PNG_SIG[k]) return null;
    const originalBytes = input.length;
    const critical = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND']);
    let pos = 8;
    let ihdr: Uint8Array | null = null;
    const otherChunks: { type: string; data: Uint8Array }[] = [];
    const idatParts: Uint8Array[] = [];
    while (pos + 8 <= input.length) {
        const len = (input[pos] << 24) | (input[pos + 1] << 16) | (input[pos + 2] << 8) | input[pos + 3];
        const typeArr = input.subarray(pos + 4, pos + 8);
        const type = String.fromCharCode(...typeArr as any);
        pos += 8;
        if (pos + len + 4 > input.length) break; // invalid
        const data = input.subarray(pos, pos + len);
        pos += len;
        const crc = input.subarray(pos, pos + 4); pos += 4; // we recalc
        if (type === 'IHDR') ihdr = data.slice();
        if (type === 'IDAT') idatParts.push(data.slice());
        else if (critical.has(type) && type !== 'IHDR' && type !== 'IDAT') {
            otherChunks.push({ type, data: data.slice() });
        } else if (!critical.has(type)) {
            continue;
        }
        if (type === 'IEND') break;
    }
    if (!ihdr || idatParts.length === 0) return null;
    let totalIdat = 0; for (const p of idatParts) totalIdat += p.length;
    const fused = new Uint8Array(totalIdat); let off = 0; for (const p of idatParts) { fused.set(p, off); off += p.length; }

    const preserved: { type: string; data: Uint8Array }[] = [];
    preserved.push({ type: 'IHDR', data: ihdr });
    for (const c of otherChunks) if (c.type !== 'IEND') preserved.push(c); // garde PLTE, etc.

    const baseSizeWithoutIDAT = 8 + preserved.reduce((acc, c) => acc + 12 + c.data.length, 0) + 12 /*IDAT header+crc*/ + fused.length + 12 /*IEND*/;

    let recompressed: Uint8Array | null = null;
    let recompressSaved = 0;
    const RECOMPRESS_THRESHOLD = 8 * 1024 * 1024; // saute recompression si trop gros pour limiter mémoire
    try {
        if (fused.length < RECOMPRESS_THRESHOLD) {
            const pako = await getPako();
            if (pako) {
                const raw = pako.inflate(fused);
                const candidate = pako.deflate(raw, { level: 9 });
                if (candidate.length < fused.length) {
                    recompressed = candidate;
                    recompressSaved = fused.length - candidate.length;
                }
            }
        }
    } catch { /* ignore */ }

    const finalIdatData = recompressed ?? fused;

    const chunks: { type: string; data: Uint8Array }[] = [...preserved, { type: 'IDAT', data: finalIdatData }, { type: 'IEND', data: new Uint8Array(0) }];
    let finalSize = 8; for (const c of chunks) finalSize += 12 + c.data.length;
    const out = new Uint8Array(finalSize);
    out.set(PNG_SIG, 0); let wpos = 8;
    for (const c of chunks) {
        const len = c.data.length;
        out[wpos++] = (len >>> 24) & 0xFF; out[wpos++] = (len >>> 16) & 0xFF; out[wpos++] = (len >>> 8) & 0xFF; out[wpos++] = len & 0xFF;
        const tBytes = new TextEncoder().encode(c.type);
        out.set(tBytes, wpos); wpos += 4;
        if (len) { out.set(c.data, wpos); wpos += len; }
        const crcInput = new Uint8Array(4 + len);
        crcInput.set(tBytes, 0); if (len) crcInput.set(c.data, 4);
        const crcVal = crc32(crcInput);
        out[wpos++] = (crcVal >>> 24) & 0xFF; out[wpos++] = (crcVal >>> 16) & 0xFF; out[wpos++] = (crcVal >>> 8) & 0xFF; out[wpos++] = crcVal & 0xFF;
    }

    const finalSizeNoRecompress = baseSizeWithoutIDAT;
    const ancillaryRemoved = originalBytes - finalSizeNoRecompress;
    const optimizedBytes = out.length;
    const totalSaved = originalBytes - optimizedBytes;
    const note = `png ancillary_removed=${ancillaryRemoved} recompress_saved=${recompressSaved} total_saved=${totalSaved}`;
    return { data: out.buffer, originalBytes, optimizedBytes, changed: optimizedBytes < originalBytes, note, format: 'png' };
}

export async function optimizeLossless(contentType: string, buf: ArrayBuffer): Promise<OptimizeResult | null> {
    try {
        const u8 = new Uint8Array(buf);
        if (contentType === 'image/png') {
            const r = await optimizePNG(u8);
            return r;
        }
        return null;
    } catch {
        return null;
    }
}
