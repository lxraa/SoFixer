"""Build minimal ELF shared objects for SoFixer tests, ELF32 and ELF64.

SoFixer consumes memory dumps, so the fixtures follow dump conventions:
p_offset == p_vaddr for every segment, and the whole image is one PT_LOAD
starting at vaddr 0. Layout is identical for both classes:

    0x0000  ELF header
    0x0034  program header table (3 entries)
    0x0100  .dynamic        (needs to sit strictly inside the PT_LOAD, else
                             ObElfReader falls back to the baseso path)
    0x0200  .eh_frame_hdr   PT_GNU_EH_FRAME points here
    0x0300  .eh_frame       CIE + 2 FDEs + terminator
    0x1000  end of image

Every corruptible field the eh_frame decoder trusts is exposed as a keyword
argument so a test can forge it.
"""

import struct

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_EH_FRAME = 0x6474E550

PF_X, PF_W, PF_R = 1, 2, 4

EM_AARCH64 = 0xB7
EM_ARM = 40
ET_DYN = 3

IMAGE_SIZE = 0x1000

DYNAMIC_VADDR = 0x100
EH_FRAME_HDR_VADDR = 0x200
EH_FRAME_VADDR = 0x300

# .eh_frame_hdr binary-search table has one (initial_loc, fde_off) pair per FDE.
FDE_COUNT = 2
EH_FRAME_HDR_SIZE = 12 + FDE_COUNT * 8

CIE_VADDR = EH_FRAME_VADDR  # 0x300, 0x10 bytes
FDE1_VADDR = 0x310  # 0x18 bytes
FDE2_VADDR = 0x328  # 0x18 bytes
LAST_FDE_END = 0x340  # last FDE ends here
EH_FRAME_END = 0x344  # ...followed by the 4-byte zero terminator

# What a correct rebuild must produce for the uncorrupted fixture.
EXPECTED_EH_FRAME_HDR = (EH_FRAME_HDR_VADDR, EH_FRAME_HDR_SIZE)
EXPECTED_EH_FRAME = (EH_FRAME_VADDR, EH_FRAME_END - EH_FRAME_VADDR)

BOTH_CLASSES = (32, 64)


def _elf_header(bits, phnum):
    if bits == 64:
        e = bytearray(64)
        e[0:4] = b"\x7fELF"
        e[4:7] = bytes([2, 1, 1])  # ELFCLASS64, ELFDATA2LSB, EV_CURRENT
        struct.pack_into("<HH", e, 16, ET_DYN, EM_AARCH64)
        struct.pack_into("<I", e, 20, 1)  # e_version
        struct.pack_into("<QQQ", e, 24, 0, 0x40, 0)  # entry, phoff, shoff
        struct.pack_into("<I", e, 48, 0)  # e_flags
        struct.pack_into("<HHH", e, 52, 64, 56, phnum)
        struct.pack_into("<HHH", e, 58, 64, 0, 0)
        return bytes(e)

    e = bytearray(52)
    e[0:4] = b"\x7fELF"
    e[4:7] = bytes([1, 1, 1])  # ELFCLASS32, ELFDATA2LSB, EV_CURRENT
    struct.pack_into("<HH", e, 16, ET_DYN, EM_ARM)
    struct.pack_into("<I", e, 20, 1)  # e_version
    struct.pack_into("<III", e, 24, 0, 0x34, 0)  # entry, phoff, shoff
    struct.pack_into("<I", e, 36, 0)  # e_flags
    struct.pack_into("<HHH", e, 40, 52, 32, phnum)
    struct.pack_into("<HHH", e, 46, 40, 0, 0)
    return bytes(e)


def phdr_offset(bits):
    return 0x40 if bits == 64 else 0x34


def phdr_size(bits):
    return 56 if bits == 64 else 32


def _phdr(bits, p_type, flags, vaddr, filesz, memsz, align=8):
    # p_offset == p_vaddr: dump convention. Note the field order differs
    # between the two classes - p_flags moves.
    if bits == 64:
        return struct.pack(
            "<IIQQQQQQ", p_type, flags, vaddr, vaddr, vaddr, filesz, memsz, align
        )
    return struct.pack(
        "<IIIIIIII", p_type, vaddr, vaddr, vaddr, filesz, memsz, flags, align
    )


def _eh_frame_bytes():
    """A CIE followed by two FDEs and the zero-length terminator record.

    SoFixer only needs the u32 length fields, but keeping the records
    well-formed means the fixture is also readable by readelf/Ghidra when a
    test fails and someone wants to look at it.
    """
    out = bytearray()

    # CIE: length 0x0c -> occupies 0x300..0x310
    cie = bytearray()
    cie += struct.pack("<I", 0)  # CIE_id
    cie += b"\x01"  # version
    cie += b"z\x00"  # augmentation
    cie += b"\x01"  # code alignment factor (uleb 1)
    cie += b"\x78"  # data alignment factor (sleb -8)
    cie += b"\x1e"  # return address register (30)
    cie += b"\x00"  # augmentation data length
    assert len(cie) <= 0x0C
    cie += b"\x00" * (0x0C - len(cie))
    out += struct.pack("<I", 0x0C) + bytes(cie)

    for pc_begin in (0x400, 0x500):
        fde = bytearray()
        fde += struct.pack("<I", len(out) + 4)  # CIE pointer (back-offset)
        fde += struct.pack("<i", pc_begin)  # initial location (pcrel sdata4)
        fde += struct.pack("<I", 0x40)  # address range
        fde += b"\x00"  # augmentation data length
        fde += b"\x00" * (0x14 - len(fde))
        out += struct.pack("<I", 0x14) + bytes(fde)

    assert EH_FRAME_VADDR + len(out) == LAST_FDE_END, hex(len(out))
    out += struct.pack("<I", 0)  # terminator record
    assert EH_FRAME_VADDR + len(out) == EH_FRAME_END
    return bytes(out)


def _eh_frame_hdr_bytes(eh_frame_ptr, fde_count, version, encodings, fde_offsets):
    ptr_enc, count_enc, table_enc = encodings
    hdr = bytearray()
    hdr += bytes([version, ptr_enc, count_enc, table_enc])
    hdr += struct.pack("<i", eh_frame_ptr)
    hdr += struct.pack("<I", fde_count)
    # Binary search table, sorted by initial location, datarel to hdr start.
    if fde_offsets is None:
        fde_offsets = [FDE1_VADDR - EH_FRAME_HDR_VADDR,
                       FDE2_VADDR - EH_FRAME_HDR_VADDR]
    for pc, fde_off in zip((0x400, 0x500), fde_offsets):
        hdr += struct.pack("<i", pc - EH_FRAME_HDR_VADDR)
        hdr += struct.pack("<i", fde_off)
    return bytes(hdr)


def build(
    path,
    bits=64,
    eh_vaddr=EH_FRAME_HDR_VADDR,
    eh_memsz=EH_FRAME_HDR_SIZE,
    eh_frame_ptr=None,
    fde_count=FDE_COUNT,
    fde_offsets=None,
    version=1,
    encodings=(0x1B, 0x03, 0x3B),
    drop_eh_phdr=False,
):
    """Write a fixture .so to `path`.

    eh_vaddr / eh_memsz forge the PT_GNU_EH_FRAME segment bounds.
    eh_frame_ptr forges the pcrel offset stored at .eh_frame_hdr+4; the default
    computes the honest one. fde_count / fde_offsets forge the binary search
    table, whose entries are datarel to the start of .eh_frame_hdr.
    """
    if eh_frame_ptr is None:
        eh_frame_ptr = EH_FRAME_VADDR - (EH_FRAME_HDR_VADDR + 4)

    phdrs = [
        _phdr(bits, PT_LOAD, PF_R | PF_X, 0, IMAGE_SIZE, IMAGE_SIZE, 0x1000),
        _phdr(bits, PT_DYNAMIC, PF_R | PF_W, DYNAMIC_VADDR, 16, 16),
    ]
    if not drop_eh_phdr:
        phdrs.append(
            _phdr(bits, PT_GNU_EH_FRAME, PF_R, eh_vaddr, eh_memsz, eh_memsz, 4)
        )

    image = bytearray(IMAGE_SIZE)
    hdr = _elf_header(bits, len(phdrs))
    image[0:len(hdr)] = hdr
    off = phdr_offset(bits)
    for p in phdrs:
        image[off:off + len(p)] = p
        off += len(p)

    # .dynamic: DT_NULL only. Nothing else is needed to reach RebuildShdr.
    dyn = struct.pack("<qQ", 0, 0) if bits == 64 else struct.pack("<iI", 0, 0)
    image[DYNAMIC_VADDR:DYNAMIC_VADDR + len(dyn)] = dyn

    eh_hdr = _eh_frame_hdr_bytes(
        eh_frame_ptr, fde_count, version, encodings, fde_offsets
    )
    image[EH_FRAME_HDR_VADDR:EH_FRAME_HDR_VADDR + len(eh_hdr)] = eh_hdr

    frame = _eh_frame_bytes()
    image[EH_FRAME_VADDR:EH_FRAME_VADDR + len(frame)] = frame

    with open(path, "wb") as f:
        f.write(image)
    return path
