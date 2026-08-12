"""End-to-end tests for the PT_GNU_EH_FRAME -> section header rebuild.

SoFixer's input is a memory dump of a packed library: every field it reads is
attacker-influenced and routinely damaged. These tests run the real binary over
fixtures whose PT_GNU_EH_FRAME fields have been forged, and assert it neither
crashes nor emits a section that misdescribes the image.

Every test runs against both builds. The 32-bit build is not a rebuild of the
64-bit one - Elf_Addr narrows to uint32_t, so its address arithmetic overflows
at different places.

Run:  python -m pytest vendor/sofixer/tests -v
"""

import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_fixture  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
BINARIES = {64: ROOT / "build" / "SoFixer64.exe",
            32: ROOT / "build32" / "SoFixer32.exe"}


@pytest.fixture(params=elf_fixture.BOTH_CLASSES, ids=lambda b: f"elf{b}")
def bits(request):
    return request.param


def read_sections(path):
    """Parse the output's section header table into {name: (addr, size)}.

    Hand-rolled rather than pyelftools: a regression here produces sizes that
    exceed the file, and the point of the test is to observe that rather than
    have the parser raise on it.
    """
    data = Path(path).read_bytes()
    is64 = data[4] == 2
    if is64:
        e_shoff, = struct.unpack_from("<Q", data, 40)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    else:
        e_shoff, = struct.unpack_from("<I", data, 32)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 46)
    assert e_shoff + e_shnum * e_shentsize <= len(data), "SHT runs past EOF"

    def entry(i):
        base = e_shoff + i * e_shentsize
        sh_name, = struct.unpack_from("<I", data, base)
        if is64:
            sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", data, base + 16)
        else:
            sh_addr, sh_offset, sh_size = struct.unpack_from("<III", data, base + 12)
        return sh_name, sh_addr, sh_offset, sh_size

    _, _, str_off, str_size = entry(e_shstrndx)
    strtab = data[str_off:str_off + str_size]

    sections = {}
    for i in range(e_shnum):
        sh_name, sh_addr, _, sh_size = entry(i)
        end = strtab.find(b"\0", sh_name)
        name = strtab[sh_name:end].decode()
        if name:
            sections[name] = (sh_addr, sh_size)
    return sections


def fix(tmp_path, bits, **corruption):
    binary = BINARIES[bits]
    if not binary.exists():
        pytest.skip(f"{binary} not built")
    src = elf_fixture.build(tmp_path / "in.so", bits=bits, **corruption)
    out = tmp_path / "out.so"
    proc = subprocess.run(
        [str(binary), "-s", str(src), "-o", str(out)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"SoFixer exited {proc.returncode} "
        f"(139 / 0xC0000005 is a segfault)\n{proc.stdout}"
    )
    sections = read_sections(out)
    file_size = out.stat().st_size
    for name, (addr, size) in sections.items():
        assert addr + size <= file_size, (
            f"{name} spans {addr:#x}..{addr + size:#x}, past EOF {file_size:#x}"
        )
    return sections


class TestHonestInput:
    def test_eh_frame_hdr_matches_the_segment(self, tmp_path, bits):
        assert fix(tmp_path, bits)[".eh_frame_hdr"] == \
            elf_fixture.EXPECTED_EH_FRAME_HDR

    def test_eh_frame_size_covers_every_record_including_the_terminator(
            self, tmp_path, bits):
        """The zero-length record that ends .eh_frame is part of the section."""
        assert fix(tmp_path, bits)[".eh_frame"] == elf_fixture.EXPECTED_EH_FRAME

    def test_segment_ending_exactly_at_image_end_is_accepted(self, tmp_path, bits):
        """Boundary: the last byte of the image is still inside the image.

        The header bytes there are zero, so only .eh_frame_hdr comes out; that
        it comes out at all is the point.
        """
        vaddr = elf_fixture.IMAGE_SIZE - elf_fixture.EH_FRAME_HDR_SIZE
        assert ".eh_frame_hdr" in fix(tmp_path, bits, eh_vaddr=vaddr)


class TestForgedSegmentBounds:
    def test_segment_vaddr_outside_image_emits_nothing(self, tmp_path, bits):
        sections = fix(tmp_path, bits, eh_vaddr=0x7FFF0000)
        assert ".eh_frame_hdr" not in sections
        assert ".eh_frame" not in sections

    def test_segment_memsz_past_image_end_emits_nothing(self, tmp_path, bits):
        """A forged memsz is the only bound on the FDE table walk."""
        sections = fix(tmp_path, bits, eh_memsz=0x40000000, fde_count=0x07000000)
        assert ".eh_frame_hdr" not in sections
        assert ".eh_frame" not in sections


class TestForgedEhFramePointer:
    def test_eh_frame_pointer_outside_image_emits_no_eh_frame(self, tmp_path, bits):
        sections = fix(tmp_path, bits, eh_frame_ptr=0x7F000000)
        assert ".eh_frame_hdr" in sections, "the header itself is still sound"
        assert ".eh_frame" not in sections


class TestForgedSearchTable:
    def test_table_offset_below_the_image_cannot_wrap_the_bounds_check(
            self, tmp_path, bits):
        """A negative offset lands the FDE just under the image base.

        Computed as an address that is 4 below zero, so a bounds check written
        as `addr + 12 <= max_load` wraps into range and lets the read through.
        """
        below_base = -(elf_fixture.EH_FRAME_HDR_VADDR + 4)
        sections = fix(tmp_path, bits, fde_offsets=[below_base, below_base])
        assert sections[".eh_frame"] == elf_fixture.EXPECTED_EH_FRAME, \
            "a garbage table entry must not change how .eh_frame is sized"

    def test_omitted_search_table_still_yields_eh_frame(self, tmp_path, bits):
        """DW_EH_PE_omit for the table is legal and lld emits it.

        .eh_frame is the section worth recovering; it must not depend on the
        optional binary search table being present or decodable.
        """
        sections = fix(tmp_path, bits, encodings=(0x1B, 0x03, 0xFF))
        assert sections[".eh_frame"] == elf_fixture.EXPECTED_EH_FRAME

    def test_empty_search_table_does_not_oversize_eh_frame(self, tmp_path, bits):
        sections = fix(tmp_path, bits, fde_count=0)
        assert sections[".eh_frame"] == elf_fixture.EXPECTED_EH_FRAME
