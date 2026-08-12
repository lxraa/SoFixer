"""Build minimal AArch64 ELF64 shared objects for SoFixer tests.

SoFixer consumes memory dumps, so the fixtures follow dump conventions:
p_offset == p_vaddr for every segment, and the whole image is one PT_LOAD
starting at vaddr 0. Layout:

    0x0000  ELF header
    0x0040  program header table (3 entries)
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
EH_FRAME_END = 0x340  # last FDE ends here; 4-byte terminator follows

# What a correct rebuild must produce for the uncorrupted fixture.
EXPECTED_EH_FRAME_HDR = (EH_FRAME_HDR_VADDR, EH_FRAME_HDR_SIZE)
EXPECTED_EH_FRAME = (EH_FRAME_VADDR, EH_FRAME_END - EH_FRAME_VADDR)


def _elf_header(phnum):
    e = bytearray(64)
    e[0:4] = b"\x7fELF"
    e[4] = 2  # ELFCLASS64
    e[5] = 1  # ELFDATA2LSB
    e[6] = 1  # EV_CURRENT
    struct.pack_into("<HH", e, 16, ET_DYN, EM_AARCH64)
    struct.pack_into("<I", e, 20, 1)  # e_version
    struct.pack_into("<Q", e, 24, 0)  # e_entry
    struct.pack_into("<Q", e, 32, 0x40)  # e_phoff
    struct.pack_into("<Q", e, 40, 0)  # e_shoff
    struct.pack_into("<I", e, 48, 0)  # e_flags
    struct.pack_into("<HHH", e, 52, 64, 56, phnum)  # ehsize, phentsize, phnum
    struct.pack_into("<HHH", e, 58, 64, 0, 0)  # shentsize, shnum, shstrndx
    return bytes(e)


def _phdr(p_type, flags, vaddr, filesz, memsz, align=8):
    # p_offset == p_vaddr: dump convention.
    return struct.pack(
        "<IIQQQQQQ", p_type, flags, vaddr, vaddr, vaddr, filesz, memsz, align
    )


def _eh_frame_bytes():
    """A CIE followed by two FDEs and the terminator.

    SoFixer only reads the u32 length of the FDE with the largest offset, but
    keeping the records well-formed means the fixture is also readable by
    readelf/Ghidra when a test fails and someone wants to look at it.
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
    assert len(out) == CIE_VADDR + 0x10 - EH_FRAME_VADDR

    for pc_begin in (0x400, 0x500):
        fde = bytearray()
        fde += struct.pack("<I", len(out) + 4)  # CIE pointer (back-offset)
        fde += struct.pack("<i", pc_begin)  # initial location (pcrel sdata4)
        fde += struct.pack("<I", 0x40)  # address range
        fde += b"\x00"  # augmentation data length
        fde += b"\x00" * (0x14 - len(fde))
        out += struct.pack("<I", 0x14) + bytes(fde)

    assert EH_FRAME_VADDR + len(out) == EH_FRAME_END, hex(len(out))
    out += struct.pack("<I", 0)  # terminator
    return bytes(out)


def _eh_frame_hdr_bytes(eh_frame_ptr, fde_count, version, encodings):
    ptr_enc, count_enc, table_enc = encodings
    hdr = bytearray()
    hdr += bytes([version, ptr_enc, count_enc, table_enc])
    hdr += struct.pack("<i", eh_frame_ptr)
    hdr += struct.pack("<I", fde_count)
    # Binary search table, sorted by initial location, datarel to hdr start.
    for fde_vaddr, pc in ((FDE1_VADDR, 0x400), (FDE2_VADDR, 0x500)):
        hdr += struct.pack("<i", pc - EH_FRAME_HDR_VADDR)
        hdr += struct.pack("<i", fde_vaddr - EH_FRAME_HDR_VADDR)
    return bytes(hdr)


def build(
    path,
    eh_vaddr=EH_FRAME_HDR_VADDR,
    eh_memsz=EH_FRAME_HDR_SIZE,
    eh_frame_ptr=None,
    fde_count=FDE_COUNT,
    version=1,
    encodings=(0x1B, 0x03, 0x3B),
    drop_eh_phdr=False,
):
    """Write a fixture .so to `path`.

    eh_vaddr / eh_memsz forge the PT_GNU_EH_FRAME segment bounds.
    eh_frame_ptr forges the pcrel offset stored at .eh_frame_hdr+4; the default
    computes the honest one. fde_count forges the entry count.
    """
    if eh_frame_ptr is None:
        eh_frame_ptr = EH_FRAME_VADDR - (EH_FRAME_HDR_VADDR + 4)

    phdrs = [
        _phdr(PT_LOAD, PF_R | PF_X, 0, IMAGE_SIZE, IMAGE_SIZE, 0x1000),
        _phdr(PT_DYNAMIC, PF_R | PF_W, DYNAMIC_VADDR, 16, 16),
    ]
    if not drop_eh_phdr:
        phdrs.append(_phdr(PT_GNU_EH_FRAME, PF_R, eh_vaddr, eh_memsz, eh_memsz, 4))

    image = bytearray(IMAGE_SIZE)
    image[0:64] = _elf_header(len(phdrs))
    off = 0x40
    for p in phdrs:
        image[off:off + 56] = p
        off += 56

    # .dynamic: DT_NULL only. Nothing else is needed to reach RebuildShdr.
    image[DYNAMIC_VADDR:DYNAMIC_VADDR + 16] = struct.pack("<qQ", 0, 0)

    hdr = _eh_frame_hdr_bytes(eh_frame_ptr, fde_count, version, encodings)
    image[EH_FRAME_HDR_VADDR:EH_FRAME_HDR_VADDR + len(hdr)] = hdr

    frame = _eh_frame_bytes()
    image[EH_FRAME_VADDR:EH_FRAME_VADDR + len(frame)] = frame

    with open(path, "wb") as f:
        f.write(image)
    return path
