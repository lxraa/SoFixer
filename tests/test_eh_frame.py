"""End-to-end tests for the PT_GNU_EH_FRAME -> section header rebuild.

SoFixer's input is a memory dump of a packed library: every field it reads is
attacker-influenced and routinely damaged. These tests run the real binary over
fixtures whose PT_GNU_EH_FRAME fields have been forged, and assert it neither
crashes nor emits a section that describes bytes outside the image.

Run:  python -m pytest vendor/sofixer/tests -v
"""

import struct
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_fixture  # noqa: E402

SOFIXER = Path(__file__).resolve().parent.parent / "build" / "SoFixer64.exe"


def read_sections(path):
    """Parse the output's section header table into {name: (addr, size)}.

    Hand-rolled rather than pyelftools: a regression here produces sizes that
    exceed the file, and the point of the test is to observe that rather than
    have the parser raise on it.
    """
    data = Path(path).read_bytes()
    e_shoff, = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    assert e_shoff + e_shnum * e_shentsize <= len(data), "SHT runs past EOF"

    def entry(i):
        base = e_shoff + i * e_shentsize
        sh_name, = struct.unpack_from("<I", data, base)
        sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", data, base + 16)
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


def run_sofixer(fixture, out):
    if not SOFIXER.exists():
        pytest.skip(f"{SOFIXER} not built (cmake -DSO_64=ON && ninja)")
    proc = subprocess.run(
        [str(SOFIXER), "-s", str(fixture), "-o", str(out)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, (
        f"SoFixer exited {proc.returncode} (segfault is -11/139)\n{proc.stdout}"
    )
    return read_sections(out)


def fix(tmp_path, **corruption):
    src = elf_fixture.build(tmp_path / "in.so", **corruption)
    return run_sofixer(src, tmp_path / "out.so")


def assert_sections_within_file(out, sections):
    """No section may describe bytes the output file doesn't contain.

    Note .shstrtab legitimately sits past the end of the loaded image -
    SoFixer appends it - so the bound is the output file, not IMAGE_SIZE.
    """
    file_size = Path(out).stat().st_size
    for name, (addr, size) in sections.items():
        assert addr + size <= file_size, (
            f"{name} spans {addr:#x}..{addr + size:#x}, past EOF {file_size:#x}"
        )


class TestHonestInput:
    def test_eh_frame_hdr_matches_the_segment(self, tmp_path):
        sections = fix(tmp_path)
        assert sections[".eh_frame_hdr"] == elf_fixture.EXPECTED_EH_FRAME_HDR

    def test_eh_frame_is_located_and_sized_from_the_fde_table(self, tmp_path):
        sections = fix(tmp_path)
        assert sections[".eh_frame"] == elf_fixture.EXPECTED_EH_FRAME

    def test_segment_ending_exactly_at_image_end_is_accepted(self, tmp_path):
        """Boundary: the last byte of the image is still inside the image.

        The header bytes there are zero, so only .eh_frame_hdr comes out; that
        it comes out at all is the point.
        """
        vaddr = elf_fixture.IMAGE_SIZE - elf_fixture.EH_FRAME_HDR_SIZE
        sections = fix(tmp_path, eh_vaddr=vaddr)
        assert ".eh_frame_hdr" in sections


class TestForgedSegmentBounds:
    def test_segment_vaddr_outside_image_emits_nothing(self, tmp_path):
        sections = fix(tmp_path, eh_vaddr=0x7FFF0000)
        assert ".eh_frame_hdr" not in sections
        assert ".eh_frame" not in sections

    def test_segment_memsz_past_image_end_emits_nothing(self, tmp_path):
        """A forged memsz is the only bound on the FDE table walk."""
        sections = fix(
            tmp_path, eh_memsz=0x80000000, fde_count=0x0F000000
        )
        assert ".eh_frame_hdr" not in sections
        assert ".eh_frame" not in sections


class TestForgedEhFramePointer:
    def test_eh_frame_pointer_outside_image_emits_no_eh_frame(self, tmp_path):
        sections = fix(tmp_path, eh_frame_ptr=0x7F000000)
        assert ".eh_frame_hdr" in sections, "the header itself is still sound"
        assert ".eh_frame" not in sections

    def test_no_section_ever_describes_bytes_past_the_file(self, tmp_path):
        """Guards the unsigned underflow in the fallback size computation."""
        sections = fix(tmp_path, eh_frame_ptr=0x7F000000)
        assert_sections_within_file(tmp_path / "out.so", sections)
