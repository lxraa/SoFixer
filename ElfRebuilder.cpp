//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/4.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
#include <cstdio>
#include <cstring>
#include <cstdint>
#include "ElfRebuilder.h"
#include "elf.h"
#include "FDebug.h"


#ifdef __SO64__
#define ADDRESS_FORMAT "ll"
#else
#define ADDRESS_FORMAT ""
#endif

ElfRebuilder::ElfRebuilder(ObElfReader *elf_reader) {
    elf_reader_ = elf_reader;
}

bool ElfRebuilder::RebuildPhdr() {
    FLOGD("=============LoadDynamicSectionFromBaseSource==========RebuildPhdr=========================");


    auto phdr = (Elf_Phdr*)elf_reader_->loaded_phdr();
    for(auto i = 0; i < elf_reader_->phdr_count(); i++) {
        phdr->p_filesz = phdr->p_memsz;     // expend filesize to memsiz
        // p_paddr and p_align is not used in load, just ignore it.
        // fix file offset.
        phdr->p_paddr = phdr->p_vaddr;
        phdr->p_offset = phdr->p_vaddr;     // elf has been loaded.
        phdr++;
    }
    FLOGD("=====================RebuildPhdr End======================");
    return true;
}

bool ElfRebuilder::RebuildShdr() {
    FLOGD("=======================RebuildShdr=========================");
    // rebuilding shdr, link information
    auto base = si.load_bias;
    shstrtab.push_back('\0');

    // empty shdr
    if(true) {
        Elf_Shdr shdr = {0};
        shdrs.push_back(shdr);
    }

    // gen .dynsym
    if(si.symtab != nullptr) {
        sDYNSYM = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynsym");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNSYM;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.symtab - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;   // calc sh_size later(pad to next shdr)
        shdr.sh_link = 0;   // link to dynstr later
//        shdr.sh_info = 1;
        shdr.sh_info = 0;
#ifdef __SO64__
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x18;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x10;
#endif

        shdrs.push_back(shdr);
    }

    // gen .dynstr
    if(si.strtab != nullptr) {
        sDYNSTR = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynstr");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_STRTAB;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.strtab - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.strtabsize;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .hash
    if(si.hash != nullptr) {
        sHASH = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".hash");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_HASH;

        shdr.sh_addr = si.hash - base;
        shdr.sh_offset = shdr.sh_addr;
        // TODO 32bit, 64bit?
        shdr.sh_size = (si.nbucket + si.nchain) * sizeof(Elf_Addr) + 2 * sizeof(Elf_Addr);
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x4;

        shdrs.push_back(shdr);
    }

    // gen .rel.dyn
    if(si.rel != nullptr) {
        sRELDYN = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rel.dyn");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_REL;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.rel - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.rel_count * sizeof(Elf_Rel);
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
#ifdef __SO64__
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x18;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;
#endif

        shdrs.push_back(shdr);
    }

    if (si.plt_rela != nullptr) {
        sRELADYN = shdrs.size();
        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".rela.dyn");
        shstrtab.push_back('\0');
        shdr.sh_type = SHT_RELA;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.plt_rela - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.plt_rela_count * sizeof(Elf_Rela);
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
#ifdef __SO64__
        shdr.sh_addralign = 8;
#else
        shdr.sh_addralign = 4;
#endif
        shdr.sh_entsize = sizeof(Elf_Rela);
        shdrs.push_back(shdr);
    }
    // gen .rel.plt
    if(si.plt_rel != nullptr) {
        sRELPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        if (si.plt_type == DT_REL){
            shstrtab.append(".rel.plt");
        } else {
            shstrtab.append(".rela.plt");
        }
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_REL;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_addr = (uintptr_t)si.plt_rel - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        if (si.plt_type == DT_REL){
            shdr.sh_size = si.plt_rel_count * sizeof(Elf_Rel);
        }else {
            shdr.sh_size = si.plt_rel_count * sizeof(Elf_Rela);
        }
        shdr.sh_link = sDYNSYM;
        shdr.sh_info = 0;
#ifdef __SO64__
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x18;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;
#endif

        shdrs.push_back(shdr);
    }

    // gen.plt with .rel.plt
    if(si.plt_rel != nullptr) {
        sPLT = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".plt");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr = shdrs[sRELPLT].sh_addr + shdrs[sRELPLT].sh_size;
        shdr.sh_offset = shdr.sh_addr;
        // TODO fix size 32bit 64bit?
        shdr.sh_size = 20/*Pure code*/ + 12 * si.plt_rel_count;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen.text&ARM.extab
    if(si.plt_rel != nullptr) {
        sTEXTTAB = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".text&ARM.extab");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_addr =  shdrs[sPLT].sh_addr + shdrs[sPLT].sh_size;
        // Align 8
        while (shdr.sh_addr & 0x7) {
            shdr.sh_addr ++;
        }

        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = 0;       // calc later
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen ARM.exidx
    if(si.ARM_exidx != nullptr) {
        sARMEXIDX = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".ARM.exidx");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_ARMEXIDX;
        shdr.sh_flags = SHF_ALLOC | SHF_LINK_ORDER;
        shdr.sh_addr = (uintptr_t)si.ARM_exidx - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.ARM_exidx_count * sizeof(Elf_Addr);
        shdr.sh_link = sTEXTTAB;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;

        shdrs.push_back(shdr);
    }
    // gen .fini_array
    if(si.fini_array != nullptr) {
        sFINIARRAY = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".fini_array");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_FINI_ARRAY;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (uintptr_t)si.fini_array - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.fini_array_count * sizeof(Elf_Addr);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
#ifdef __SO64__
        shdr.sh_addralign = 8;
#else
        shdr.sh_addralign = 4;
#endif
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .init_array
    if(si.init_array != nullptr) {
        sINITARRAY = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".init_array");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_INIT_ARRAY;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (uintptr_t)si.init_array - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.init_array_count * sizeof(Elf_Addr);
        shdr.sh_link = 0;
        shdr.sh_info = 0;
#ifdef __SO64__
        shdr.sh_addralign = 8;
#else
        shdr.sh_addralign = 4;
#endif
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .dynamic
    if(si.dynamic != nullptr) {
        sDYNAMIC = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".dynamic");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_DYNAMIC;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = (uintptr_t)si.dynamic - (uintptr_t)base;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.dynamic_count * sizeof(Elf_Dyn);
        shdr.sh_link = sDYNSTR;
        shdr.sh_info = 0;
#ifdef __SO64__
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0x10;
#else
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x8;
#endif

        shdrs.push_back(shdr);
    }

    // get .got
//    if(si.plt_got != nullptr) {
//        // global_offset_table
//        sGOT = shdrs.size();
//        auto sLast = sGOT - 1;
//
//        Elf_Shdr shdr;
//        shdr.sh_name = shstrtab.length();
//        shstrtab.append(".got");
//        shstrtab.push_back('\0');
//
//        shdr.sh_type = SHT_PROGBITS;
//        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
//        shdr.sh_addr = shdrs[sLast].sh_addr + shdrs[sLast].sh_size;
//        // Align8??
//        while (shdr.sh_addr & 0x7) {
//            shdr.sh_addr ++;
//        }
//
//        shdr.sh_offset = shdr.sh_addr;
//        shdr.sh_size = (uintptr_t)(si.plt_got + si.plt_rel_count) - shdr.sh_addr - (uintptr_t)base + 3 * sizeof(Elf_Addr);
//        shdr.sh_link = 0;
//        shdr.sh_info = 0;
//#ifdef __SO64__
//        shdr.sh_addralign = 8;
//#else
//        shdr.sh_addralign = 4;
//#endif
//        shdr.sh_entsize = 0x0;
//
//        shdrs.push_back(shdr);
//    }

    // gen .data
    if(true) {
        sDATA = shdrs.size();
        auto sLast = sDATA - 1;

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".data");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_addr = shdrs[sLast].sh_addr + shdrs[sLast].sh_size;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = si.max_load - shdr.sh_addr;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // gen .bss
//    if(true) {
//        sBSS = shdrs.size();
//
//        Elf_Shdr shdr;
//        shdr.sh_name = shstrtab.length();
//        shstrtab.append(".bss");
//        shstrtab.push_back('\0');
//
//        shdr.sh_type = SHT_NOBITS;
//        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
//        shdr.sh_addr = si.max_load;
//        shdr.sh_offset = shdr.sh_addr;
//        shdr.sh_size = 0;   // not used
//        shdr.sh_link = 0;
//        shdr.sh_info = 0;
//        shdr.sh_addralign = 8;
//        shdr.sh_entsize = 0x0;
//
//        shdrs.push_back(shdr);
//    }

    // gen .eh_frame_hdr and .eh_frame from PT_GNU_EH_FRAME.
    // Packed libil2cpp.so (yidun/tp/mihoyo) wipes ELF header but leaves PHT
    // intact; PT_GNU_EH_FRAME survives because the runtime needs it for C++
    // unwind. Promoting them to section headers lets Ghidra/IDA use unwind
    // tables for function boundary detection on the dumped binary.
    {
        auto eh_phdr_table = (const Elf_Phdr*)elf_reader_->loaded_phdr();
        const Elf_Phdr* eh_phdr = nullptr;
        for (auto i = 0; i < elf_reader_->phdr_count(); i++) {
            if (eh_phdr_table[i].p_type == PT_GNU_EH_FRAME) {
                eh_phdr = &eh_phdr_table[i];
                break;
            }
        }

        // The segment bounds come from the dump and are untrusted: a packer can
        // leave a fabricated or stale PT_GNU_EH_FRAME behind. Require the whole
        // segment to describe bytes we actually hold before reading any of it —
        // p_memsz is also the only bound on the FDE table walk further down.
        // Written as a subtraction so it cannot wrap on the 32-bit build.
        bool eh_within_image = eh_phdr != nullptr &&
                               eh_phdr->p_memsz >= 12 &&
                               eh_phdr->p_vaddr >= si.min_load &&
                               eh_phdr->p_vaddr <= si.max_load &&
                               eh_phdr->p_memsz <= si.max_load - eh_phdr->p_vaddr;
        if (eh_phdr != nullptr && !eh_within_image) {
            FLOGD("PT_GNU_EH_FRAME [%" ADDRESS_FORMAT "x, +%" ADDRESS_FORMAT "x) "
                  "unusable against loaded image [%" ADDRESS_FORMAT "x, %" ADDRESS_FORMAT "x); "
                  "no unwind sections emitted",
                  eh_phdr->p_vaddr, eh_phdr->p_memsz, si.min_load, si.max_load);
        }

        if (eh_within_image) {
            // gen .eh_frame_hdr (always — straight copy of PT segment bounds)
            sEHFRAMEHDR = shdrs.size();

            Elf_Shdr shdr;
            shdr.sh_name = shstrtab.length();
            shstrtab.append(".eh_frame_hdr");
            shstrtab.push_back('\0');

            shdr.sh_type = SHT_PROGBITS;
            shdr.sh_flags = SHF_ALLOC;
            shdr.sh_addr = eh_phdr->p_vaddr;
            shdr.sh_offset = shdr.sh_addr;
            shdr.sh_size = eh_phdr->p_memsz;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = 4;
            shdr.sh_entsize = 0;
            shdrs.push_back(shdr);

            // Decode .eh_frame_hdr to locate .eh_frame. Standard GCC/Clang
            // Android NDK layout:
            //   byte 0 = version (1)
            //   byte 1 = eh_frame_ptr_enc (expect 0x1b: DW_EH_PE_pcrel|sdata4)
            //   byte 2 = fde_count_enc
            //   byte 3 = table_enc
            //   bytes 4..7  = eh_frame_ptr (s32, pcrel from byte 4)
            //   bytes 8..11 = fde_count, then the binary search table.
            // Only the first two are read. The search table is optional
            // (DW_EH_PE_omit), its entries are untrusted, and .eh_frame is
            // self-describing, so the size comes from walking it instead.
            // An unsupported eh_frame_ptr encoding falls back to emitting
            // .eh_frame_hdr only; Ghidra can still consume PT_GNU_EH_FRAME
            // directly in that case.
            auto* hdr_bytes = (const uint8_t*)(base + eh_phdr->p_vaddr);
            if (hdr_bytes[0] == 1 && hdr_bytes[1] == 0x1b) {
                int32_t eh_frame_off;
                memcpy(&eh_frame_off, hdr_bytes + 4, 4);

                Elf_Addr eh_frame_vaddr =
                    eh_phdr->p_vaddr + 4 + (int64_t)eh_frame_off;
                bool eh_frame_within_image =
                    eh_frame_vaddr >= si.min_load && eh_frame_vaddr < si.max_load;
                if (!eh_frame_within_image) {
                    FLOGD("eh_frame_ptr resolves to %" ADDRESS_FORMAT "x, outside "
                          "loaded image [%" ADDRESS_FORMAT "x, %" ADDRESS_FORMAT "x); "
                          "only .eh_frame_hdr emitted",
                          eh_frame_vaddr, si.min_load, si.max_load);
                }

                // Size .eh_frame by walking its record chain. Every record is
                // a u32 length followed by that many bytes; 0xffffffff means
                // the real length is the u64 that follows; a zero length is
                // the terminator, and those 4 bytes belong to the section.
                //
                // Every bound is a subtraction against max_load rather than an
                // addition compared to it, so a forged length cannot wrap into
                // range - on the 32-bit build Elf_Addr is only 32 bits wide.
                // The cursor advances by at least 4 per iteration, so a corrupt
                // chain terminates rather than spinning.
                bool size_known = false;
                size_t eh_frame_size = 0;
                if (eh_frame_within_image) {
                    Elf_Addr cursor = eh_frame_vaddr;
                    while (si.max_load - cursor >= 4) {
                        uint32_t len32;
                        memcpy(&len32, base + cursor, 4);
                        Elf_Addr body = cursor + 4;
                        if (len32 == 0) {
                            cursor = body;      // terminator; section ends here
                            break;
                        }
                        uint64_t len = len32;
                        if (len32 == 0xffffffff) {
                            if (si.max_load - body < 8) break;
                            memcpy(&len, base + body, 8);
                            body += 8;
                        }
                        if (len > si.max_load - body) break;  // runs past image
                        cursor = body + len;
                    }
                    if (cursor > eh_frame_vaddr) {
                        eh_frame_size = cursor - eh_frame_vaddr;
                        size_known = true;
                    }
                }

                // eh_frame_ptr is untrusted too. A vaddr outside the image
                // makes the fallback size below underflow, and such a section
                // sorts last, where the fix-size pass can no longer clamp it.
                if (eh_frame_within_image) {
                    sEHFRAME = shdrs.size();

                    Elf_Shdr ef_shdr;
                    ef_shdr.sh_name = shstrtab.length();
                    shstrtab.append(".eh_frame");
                    shstrtab.push_back('\0');

                    ef_shdr.sh_type = SHT_PROGBITS;
                    ef_shdr.sh_flags = SHF_ALLOC;
                    ef_shdr.sh_addr = eh_frame_vaddr;
                    ef_shdr.sh_offset = ef_shdr.sh_addr;
                    // If size_known, use it. Otherwise upper-bound to load end;
                    // the post-sort fix-size pass will clamp to the next section.
                    ef_shdr.sh_size = size_known ?
                        eh_frame_size :
                        (si.max_load - eh_frame_vaddr);
                    ef_shdr.sh_link = 0;
                    ef_shdr.sh_info = 0;
                    ef_shdr.sh_addralign = 8;
                    ef_shdr.sh_entsize = 0;
                    shdrs.push_back(ef_shdr);
                }
            } else {
                FLOGD("eh_frame_hdr uses non-default encoding "
                      "(ver=%d ptr=0x%x fde=0x%x tbl=0x%x); "
                      "only .eh_frame_hdr emitted",
                      hdr_bytes[0], hdr_bytes[1], hdr_bytes[2], hdr_bytes[3]);
            }
        }
    }

    // gen .shstrtab, pad into last data
    if(true) {
        sSHSTRTAB = shdrs.size();

        Elf_Shdr shdr;
        shdr.sh_name = shstrtab.length();
        shstrtab.append(".shstrtab");
        shstrtab.push_back('\0');

        shdr.sh_type = SHT_STRTAB;
        shdr.sh_flags = 0;
        shdr.sh_addr = si.max_load;
        shdr.sh_offset = shdr.sh_addr;
        shdr.sh_size = shstrtab.length();
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0x0;

        shdrs.push_back(shdr);
    }

    // link section data

    // sort shdr and recalc size
    for(auto i = 1; i < shdrs.size(); i++) {
        for(auto j = i + 1; j < shdrs.size(); j++) {
            if(shdrs[i].sh_addr > shdrs[j].sh_addr) {
                // exchange i, j
                auto tmp = shdrs[i];
                shdrs[i] = shdrs[j];
                shdrs[j] = tmp;

                // exchange index
                auto chgIdx = [i, j](Elf_Word &t) {
                    if(t == i) {
                        t = j;
                    } else if(t == j) {
                        t = i;
                    }
                };
                chgIdx(sDYNSYM);
                chgIdx(sDYNSTR);
                chgIdx(sHASH);
                chgIdx(sRELDYN);
                chgIdx(sRELADYN);
                chgIdx(sRELPLT);
                chgIdx(sPLT);
                chgIdx(sTEXTTAB);
                chgIdx(sARMEXIDX);
                chgIdx(sFINIARRAY);
                chgIdx(sINITARRAY);
                chgIdx(sDYNAMIC);
                chgIdx(sGOT);
                chgIdx(sDATA);
                chgIdx(sBSS);
                chgIdx(sEHFRAMEHDR);
                chgIdx(sEHFRAME);
                chgIdx(sSHSTRTAB);
            }
        }
    }
    if (sHASH != 0) {
        shdrs[sHASH].sh_link = sDYNSYM;
    }
    if (sRELDYN != 0){
        shdrs[sRELDYN].sh_link = sDYNSYM;
    }
    if (sRELADYN != 0){
        shdrs[sRELADYN].sh_link = sDYNSYM;
    }
    if (sRELPLT != 0) {
        shdrs[sRELPLT].sh_link = sDYNSYM;
    }
    if (sARMEXIDX != 0) {
        shdrs[sARMEXIDX].sh_link = sTEXTTAB;
    }
    if (sDYNAMIC != 0) {
        shdrs[sDYNAMIC].sh_link = sDYNSTR;
    }
    if(sDYNSYM != 0) {
        shdrs[sDYNSYM].sh_link = sDYNSTR;
    }

    if(sDYNSYM != 0) {
        auto sNext = sDYNSYM + 1;
        shdrs[sDYNSYM].sh_size = shdrs[sNext].sh_addr - shdrs[sDYNSYM].sh_addr;
    }

    if(sTEXTTAB != 0) {
        auto sNext = sTEXTTAB + 1;
        shdrs[sTEXTTAB].sh_size = shdrs[sNext].sh_addr - shdrs[sTEXTTAB].sh_addr;
    }

    // fix for size
    for(auto i = 2; i < shdrs.size(); i++) {
        if(shdrs[i].sh_offset - shdrs[i-1].sh_offset < shdrs[i-1].sh_size) {
            shdrs[i-1].sh_size = shdrs[i].sh_offset - shdrs[i-1].sh_offset;
        }
    }

    FLOGD("=====================RebuildShdr End======================");
    return true;
}

bool ElfRebuilder::Rebuild() {
    return RebuildPhdr() &&
           ReadSoInfo() &&
           RebuildShdr() &&
           RebuildRelocs() &&
           RebuildFin();
}

bool ElfRebuilder::ReadSoInfo() {
    FLOGD("=======================ReadSoInfo=========================");
    si.base = si.load_bias = elf_reader_->load_bias();
    si.phdr = elf_reader_->loaded_phdr();
    si.phnum = elf_reader_->phdr_count();
    auto base = si.load_bias;
    phdr_table_get_load_size(si.phdr, si.phnum, &si.min_load, &si.max_load);
    si.max_load += elf_reader_->pad_size_;

    /* Extract dynamic section */
    elf_reader_->GetDynamicSection(&si.dynamic, &si.dynamic_count, &si.dynamic_flags);
    if(si.dynamic == nullptr) {
        FLOGE("No valid dynamic phdr data");
        return false;
    }

    phdr_table_get_arm_exidx(si.phdr, si.phnum, si.base,
                             &si.ARM_exidx, (unsigned*)&si.ARM_exidx_count);

    // Extract useful information from dynamic section.
    uint32_t needed_count = 0;
    for (Elf_Dyn* d = si.dynamic; d->d_tag != DT_NULL; ++d) {
        switch(d->d_tag){
            case DT_HASH:
                si.hash = d->d_un.d_ptr + (uint8_t*)base;
                si.nbucket = ((unsigned *) (base + d->d_un.d_ptr))[0];
                si.nchain = ((unsigned *) (base + d->d_un.d_ptr))[1];
                si.bucket = (unsigned *) (base + d->d_un.d_ptr + 8);
                si.chain = (unsigned *) (base + d->d_un.d_ptr + 8 + si.nbucket * 4);
                break;
            case DT_STRTAB:
                si.strtab = (const char *) (base + d->d_un.d_ptr);
                FLOGD("string table found at %" ADDRESS_FORMAT "x", d->d_un.d_ptr);
                break;
            case DT_SYMTAB:
                si.symtab = (Elf_Sym *) (base + d->d_un.d_ptr);
                FLOGD("symbol table found at %" ADDRESS_FORMAT "x", d->d_un.d_ptr);
                break;
            case DT_PLTREL:
                si.plt_type = d->d_un.d_val;
                break;
            case DT_JMPREL:
                si.plt_rel = (Elf_Rel*) (base + d->d_un.d_ptr);
                FLOGD("%s plt_rel (DT_JMPREL) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                si.plt_rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                FLOGD("%s plt_rel_count (DT_PLTRELSZ) %zu", si.name, si.plt_rel_count);
                break;
            case DT_REL:
                si.rel = (Elf_Rel*) (base + d->d_un.d_ptr);
                FLOGD("%s rel (DT_REL) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                si.rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                FLOGD("%s rel_size (DT_RELSZ) %zu", si.name, si.rel_count);
                break;
            case DT_PLTGOT:
                /* Save this in case we decide to do lazy binding. We don't yet. */
                si.plt_got = (Elf_Addr *)(base + d->d_un.d_ptr);
                break;
            case DT_DEBUG:
                // Set the DT_DEBUG entry to the address of _r_debug for GDB
                // if the dynamic table is writable
                break;
            case DT_RELA:
                si.plt_rela = (Elf_Rela*)(base + d->d_un.d_ptr);
                break;
            case DT_RELASZ:
                si.plt_rela_count = d->d_un.d_val / sizeof(Elf_Rela);
                break;
            case DT_INIT:
                si.init_func = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_INIT) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_FINI:
                si.fini_func = reinterpret_cast<void*>(base + d->d_un.d_ptr);
                FLOGD("%s destructors (DT_FINI) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAY:
                si.init_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_INIT_ARRAY) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                si.init_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                FLOGD("%s constructors (DT_INIT_ARRAYSZ) %zu", si.name, si.init_array_count);
                break;
            case DT_FINI_ARRAY:
                si.fini_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                FLOGD("%s destructors (DT_FINI_ARRAY) found at %" ADDRESS_FORMAT "x", si.name, d->d_un.d_ptr);
                break;
            case DT_FINI_ARRAYSZ:
                si.fini_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                FLOGD("%s destructors (DT_FINI_ARRAYSZ) %zu", si.name, si.fini_array_count);
                break;
            case DT_PREINIT_ARRAY:
                si.preinit_array = reinterpret_cast<void**>(base + d->d_un.d_ptr);
                FLOGD("%s constructors (DT_PREINIT_ARRAY) found at %" ADDRESS_FORMAT "d", si.name, d->d_un.d_ptr);
                break;
            case DT_PREINIT_ARRAYSZ:
                si.preinit_array_count = ((unsigned)d->d_un.d_val) / sizeof(Elf_Addr);
                FLOGD("%s constructors (DT_PREINIT_ARRAYSZ) %zu", si.name, si.preinit_array_count);
                break;
            case DT_TEXTREL:
                si.has_text_relocations = true;
                break;
            case DT_SYMBOLIC:
                si.has_DT_SYMBOLIC = true;
                break;
            case DT_NEEDED:
                ++needed_count;
                break;
            case DT_FLAGS:
                if (d->d_un.d_val & DF_TEXTREL) {
                    si.has_text_relocations = true;
                }
                if (d->d_un.d_val & DF_SYMBOLIC) {
                    si.has_DT_SYMBOLIC = true;
                }
                break;
            case DT_STRSZ:
                si.strtabsize = d->d_un.d_val;
                break;
            case DT_SYMENT:
            case DT_RELENT:
                break;
            case DT_MIPS_RLD_MAP:
                // Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB.
                break;
            case DT_MIPS_RLD_VERSION:
            case DT_MIPS_FLAGS:
            case DT_MIPS_BASE_ADDRESS:
            case DT_MIPS_UNREFEXTNO:
                break;

            case DT_MIPS_SYMTABNO:
                si.mips_symtabno = d->d_un.d_val;
                break;

            case DT_MIPS_LOCAL_GOTNO:
                si.mips_local_gotno = d->d_un.d_val;
                break;

            case DT_MIPS_GOTSYM:
                si.mips_gotsym = d->d_un.d_val;
                break;
            case DT_SONAME:
                si.name = (const char *) (base + d->d_un.d_ptr);
                FLOGD("soname %s", si.name);
                break;
            default:
                FLOGD("Unused DT entry: type 0x%08" ADDRESS_FORMAT "x arg 0x%08" ADDRESS_FORMAT "x", d->d_tag, d->d_un.d_val);
                break;
        }
    }
    FLOGD("=======================ReadSoInfo End=========================");
    return true;
}

// Finally, generate rebuild_data
bool ElfRebuilder::RebuildFin() {
    FLOGD("=======================try to finish file rebuild =========================");
    auto load_size = si.max_load - si.min_load;
    rebuild_size = load_size + shstrtab.length() +
                   shdrs.size() * sizeof(Elf_Shdr);
    rebuild_data = new uint8_t[rebuild_size];
    memcpy(rebuild_data, (void*)si.load_bias, load_size);
    // pad with shstrtab
    memcpy(rebuild_data + load_size, shstrtab.c_str(), shstrtab.length());
    // pad with shdrs
    auto shdr_off = load_size + shstrtab.length();
    memcpy(rebuild_data + (int)shdr_off, (void*)&shdrs[0],
           shdrs.size() * sizeof(Elf_Shdr));
    auto ehdr = *elf_reader_->record_ehdr();
    ehdr.e_type = ET_DYN;
#ifdef __SO64__
    ehdr.e_machine = 183;
#else
    ehdr.e_machine = 40;
#endif
    ehdr.e_shnum = shdrs.size();
    ehdr.e_shoff = (Elf_Addr)shdr_off;
    ehdr.e_shstrndx = sSHSTRTAB;
    memcpy(rebuild_data, &ehdr, sizeof(Elf_Ehdr));

    FLOGD("=======================End=========================");
    return true;
}

template <bool isRela>
void ElfRebuilder::relocate(uint8_t * base, Elf_Rel* rel, Elf_Addr dump_base) {
    if(rel == nullptr) return ;
#ifndef __SO64__
    auto type = ELF32_R_TYPE(rel->r_info);
    auto sym = ELF32_R_SYM(rel->r_info);
#else
    auto type = ELF64_R_TYPE(rel->r_info);
    auto sym = ELF64_R_SYM(rel->r_info);
#endif
    auto prel = reinterpret_cast<Elf_Addr *>(base + rel->r_offset);
    switch (type) {
        // I don't known other so info, if i want to fix it, I must dump other so file
        case R_386_RELATIVE:
        case R_ARM_RELATIVE:
            *prel = *prel - dump_base;
            break;
        case 0x402:{
            auto syminfo = si.symtab[sym];
            if (syminfo.st_value != 0) {
                *prel = syminfo.st_value;
            } else {
                auto load_size = si.max_load - si.min_load;
                *prel = load_size + external_pointer;
                external_pointer += sizeof(*prel);
            }
            break;
        }
        default:
            break;
    }
    if (isRela){
        Elf_Rela* rela = (Elf_Rela*)rel;
        switch (type){
            case 0x403:
                *prel = rela->r_addend;
                break;
            default:
                break;
        }
    }
};


bool ElfRebuilder::RebuildRelocs() {
    if(elf_reader_->dump_so_base_ == 0) return true;
    FLOGD("=======================RebuildRelocs=========================");
    if (si.plt_type == DT_REL) {
        auto rel = si.rel;
        for (auto i = 0; i < si.rel_count; i++, rel++){
            relocate<false>(si.load_bias, rel, elf_reader_->dump_so_base_);
        }
        rel = si.plt_rel;
        for (auto i = 0; i < si.plt_rel_count; i++, rel++){
            relocate<false>(si.load_bias, rel, elf_reader_->dump_so_base_);
        }
    } else {
        auto rel = (Elf_Rela*)si.plt_rela;
        for (auto i = 0; i <si.plt_rela_count; i++, rel ++) {
            relocate<true>(si.load_bias, (Elf_Rel*)rel, elf_reader_->dump_so_base_);
        }
        rel = (Elf_Rela*) si.plt_rel;
        for (auto i = 0; i < si.plt_rel_count; i++, rel++){
            relocate<true>(si.load_bias, (Elf_Rel*)rel, elf_reader_->dump_so_base_);
        }
    }
    auto relocate_address = [](Elf_Addr * pelf, Elf_Addr dump_base){
        if (*pelf > dump_base)
            *pelf = *pelf - dump_base;
    };
//        relocate_address(p, elf_reader_->dump_so_base_);
//        relocate_address(p, elf_reader_->dump_so_base_);
    FLOGD("=======================RebuildRelocs End=======================");
    return true;
}




