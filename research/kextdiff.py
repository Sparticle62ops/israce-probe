#!/usr/bin/env python3
# Kernelcache kext-level differ for iOS 24A446 vs 24B119 (iPhone18,5).
# Kernelcaches here are already-decrypted Mach-O filesets (LC_FILESET_ENTRY cmd 0x80000035):
# entry vmaddr at +8, file offset at +16, inline kext name at +32.
# Emits per-kext size + changed-byte-fraction, plus region list for a named kext.
import struct, json, sys

def fileset_entries(path):
    b = open(path, 'rb').read()
    ncmds, sizeofcmds = struct.unpack_from('<II', b, 16)
    off = 32
    ent = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', b, off)
        if cmd == 0x80000035:
            vm = struct.unpack_from('<Q', b, off + 8)[0]
            fo = struct.unpack_from('<Q', b, off + 16)[0]
            name = b[off+32:off+cmdsize].split(b'\x00')[0].decode(errors='replace')
            ent.append([name, fo, vm])
        off += cmdsize
    ent.sort(key=lambda e: e[1])
    for i, e in enumerate(ent):
        e.append((ent[i+1][1] - e[1]) if i+1 < len(ent) else (len(b) - e[1]))
    return b, ent

def regions(ca, cb, gap=8):
    offs = [i for i in range(min(len(ca), len(cb))) if ca[i] != cb[i]]
    if not offs: return []
    out = []; s = p = offs[0]
    for o in offs[1:]:
        if o - p <= gap: p = o
        else: out.append((s, p)); s = p = o
    out.append((s, p))
    return out

if __name__ == '__main__':
    a_path, b_path = sys.argv[1], sys.argv[2]
    a_bytes, a = fileset_entries(a_path)
    b_bytes, b2 = fileset_entries(b_path)
    ia = {e[0]: e for e in a}; ib = {e[0]: e for e in b2}
    print(f"{len(a)} kexts | {len(b2)} kexts")
    for name in sorted(set(ia) & set(ib)):
        ea, eb = ia[name], ib[name]
        ca = a_bytes[ea[1]:ea[1]+ea[3]]; cb = b_bytes[eb[1]:eb[1]+eb[3]]
        diff = sum(1 for x, y in zip(ca, cb) if x != y)
        if diff > 8:
            print(f"{name}: {ea[3]} -> {eb[3]} bytes, {diff} differ ({100*diff/max(1,len(ca)):.2f}%)")
    if len(sys.argv) > 3:
        name = sys.argv[3]
        ea, eb = ia[name], ib[name]
        regs = regions(a_bytes[ea[1]:ea[1]+ea[3]], b_bytes[eb[1]:eb[1]+eb[3]])
        print(json.dumps({'a_off': ea[1], 'a_vm': ea[2], 'b_off': eb[1], 'b_vm': eb[2], 'regions': regs}))
