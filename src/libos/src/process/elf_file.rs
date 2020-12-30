use crate::prelude::*;
use std::fmt;
use std::str;

use crate::scroll::ctx::SizeWith;
use goblin::container::{Container, Ctx};
pub use goblin::elf::header::Header as ElfHeader;
use goblin::elf::{program_header, section_header, Elf, ProgramHeader, SectionHeader};
use goblin::elf64::header::ET_DYN;
use goblin::strtab::*;
use rcore_fs::vfs::INode;
use scroll::{self, ctx, Pread};
use std::mem;

const ELF64_HDR_SIZE: usize = 64;

pub struct ElfFile<'a> {
    elf_buf: &'a [u8],
    elf_inner: Elf<'a>,
    file_inode: Arc<dyn INode>,
}

impl<'a> Debug for ElfFile<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ElfFile {{ inode: ???, elf_buf: {:?}, elf_inner: {:?} }}",
            self.elf_buf, self.elf_inner,
        )
    }
}

impl<'a> ElfFile<'a> {
    pub fn new(
        file_inode: Arc<dyn INode>,
        mut elf_buf: &'a mut [u8],
        header: ElfHeader,
    ) -> Result<ElfFile> {
        let ctx = Ctx {
            le: scroll::Endian::Little,
            container: Container::Big,
        };
        let program_headers = ProgramHeader::parse(
            elf_buf,
            header.e_phoff as usize,
            header.e_phnum as usize,
            ctx,
        )
        .map_err(|e| errno!(ENOEXEC, "invalid program headers"))?;

        // read interpreter path
        let mut count = 0;
        let mut offset = 0;
        let mut intepreter_count = 0;
        let mut intepreter_offset = 0;
        for ph in &program_headers {
            ph.validate()?;
            if ph.p_type == program_header::PT_INTERP && ph.p_filesz != 0 {
                intepreter_count = ph.p_filesz as usize;
                intepreter_offset = ph.p_offset as usize;
                println!(
                    "PT_INTERP offset = {}, count = {}",
                    intepreter_offset, intepreter_count
                );
                file_inode.read_at(
                    intepreter_offset,
                    &mut elf_buf[intepreter_offset..intepreter_offset + intepreter_count],
                );
                continue;
            }

            if ph.p_type == program_header::PT_LOAD {
                count = ph.p_filesz as usize;
                offset = ph.p_offset as usize;
                println!("PT_LOAD offset = {}, count = {}", offset, count);
                file_inode.read_at(offset, &mut elf_buf[offset..offset + count]);
            }
        }

        let interpreter = if intepreter_count == 0 {
            None
        } else {
            str::from_utf8(&elf_buf[intepreter_offset..intepreter_offset + intepreter_count]).ok()
        };
        println!("interpreter = {:?}", interpreter);

        let section_headers = SectionHeader::parse(
            elf_buf,
            header.e_shoff as usize,
            header.e_shnum as usize,
            ctx,
        )
        .map_err(|e| errno!(ENOEXEC, "invalid section headers"))?;
        // let get_strtab = |section_headers: &[SectionHeader], section_idx: usize| {
        //     if section_idx >= section_headers.len() {
        //         // FIXME: warn! here
        //         return_errno!(ENOEXEC, "section string table parsing error");
        //     } else {
        //         let shdr = &section_headers[section_idx];
        //         shdr.check_size(elf_buf.len()).map_err(|e| errno!(ENOEXEC, "invalid section header size"))?;

        //         Strtab::parse(elf_buf, shdr.sh_offset as usize, shdr.sh_size as usize, 0x0).map_err(|e| errno!(ENOEXEC, "parsing section string table failure"))
        //     }
        // };

        let strtab_idx = header.e_shstrndx as usize;
        let strtab_shdr = &section_headers[strtab_idx];
        // read string table
        file_inode.read_at(
            strtab_shdr.sh_offset as usize,
            &mut elf_buf[strtab_shdr.sh_offset as usize
                ..(strtab_shdr.sh_offset + strtab_shdr.sh_size) as usize],
        );
        // let shdr_strtab = get_strtab(&section_headers, strtab_idx)
        //     .map_err(|e| errno!(ENOEXEC, "invalid section header string table"))?;

        let mut strtab = Strtab::parse(
            &mut elf_buf,
            strtab_shdr.sh_offset as usize,
            strtab_shdr.sh_size as usize,
            0x0,
        )
        .map_err(|e| errno!(ENOEXEC, "parsing section string table failure"))?;
        println!("shdr_strtab = {:?}", strtab);

        let mut read_vec = Vec::with_capacity(4);
        for (idx, section) in section_headers.iter().enumerate() {
            let is_progbits = section.sh_type == section_header::SHT_PROGBITS;
            let section_name = strtab.get(section.sh_name).unwrap().unwrap();
            println!("[{}] section_name = {:?}", idx, section_name);
            if section_name == ".fini" {
                //file_inode.read_at(section.sh_offset as usize, &mut elf_buf[section.sh_offset as usize..(section.sh_offset+section.sh_size) as usize]);
                println!(
                    "1 .fini sh_offset = {}, sh_size = {}",
                    section.sh_offset, section.sh_size
                );
                read_vec.push(
                    section.sh_offset as usize..(section.sh_offset + section.sh_size) as usize,
                );
                break;
            }
            //section.check_size(elf_buf.len()).map_err(|e| errno!(EINVAL, "section size not valid"))?;
            // file_inode.read_at(section.sh_offset as usize, &mut elf_buf[section.sh_offset as usize..(section.sh_offset+section.sh_size) as usize]);
            // let sh_relocs = RelocSection::parse(elf_buf, section.sh_offset as usize, section.sh_size as usize, is_rela, ctx)?;
        }
        // read_vec.iter().for_each(|range| {
        //     println!("2 .fini sh_offset = {}, sh_size = {}", range.start, range.end - range.start);
        //     file_inode.read_at(range.start, &mut elf_buf[range.start..range.end]);
        // });

        let elf_inner =
            goblin::elf::Elf::parse(elf_buf).map_err(|e| errno!(ENOEXEC, "invalid ELF format"))?;
        println!("dynrelas = {:?}", elf_inner.dynrelas);
        println!("pltrelocs = {:?}", elf_inner.pltrelocs);
        println!("shdr_relocs = {:?}", elf_inner.shdr_relocs);
        println!("dynrels = {:?}", elf_inner.dynrels);
        // println!("dynrelas = {:?}", elf_inner.dynrelas);

        Ok(ElfFile {
            elf_buf,
            elf_inner,
            file_inode,
        })
    }

    pub fn program_headers<'b>(&'b self) -> impl Iterator<Item = &'b ProgramHeader> {
        self.elf_inner.program_headers.iter()
    }

    pub fn elf_header(&self) -> &ElfHeader {
        &self.elf_inner.header
    }

    pub fn elf_interpreter(&self) -> Option<&'a str> {
        self.elf_inner.interpreter
    }

    pub fn as_slice(&self) -> &[u8] {
        self.elf_buf
    }

    // parse elf header and read in program headers and section headers
    pub fn parse_elf_hdr_to_read_pshdrs(
        inode: Arc<dyn INode>,
        elf_buf: &mut Vec<u8>,
    ) -> Result<(&Vec<u8>, ElfHeader)> {
        // TODO: Sanity check the number of program headers..
        let mut phdr_start = 0;
        let mut phdr_end = 0;

        let hdr_size = ELF64_HDR_SIZE;
        let elf_hdr =
            Elf::parse_elf_hdr(&elf_buf).map_err(|e| errno!(ENOEXEC, "invalid ELF header"))?;

        // executables built with -fPIE are type ET_DYN (shared object file)
        if elf_hdr.e_type != ET_DYN {
            return_errno!(ENOEXEC, "ELF is not position-independent");
        }

        if elf_hdr.e_phnum == 0 {
            return_errno!(ENOEXEC, "ELF doesn't have any program segments");
        }

        // OS need this
        let program_hdr_table_size = elf_hdr.e_phnum * elf_hdr.e_phentsize;
        inode.read_at(
            elf_hdr.e_phoff as usize,
            &mut elf_buf[hdr_size..hdr_size + (program_hdr_table_size as usize)],
        )?;

        // loader might need this
        if elf_hdr.e_shoff == 0 {
            // Zero offset means no section headers, not even the null section header.
            return Ok((elf_buf, elf_hdr));
        }
        let ctx = Ctx {
            le: scroll::Endian::Little,
            container: Container::Big,
        };
        let section_hdrs_size = elf_hdr.e_shnum as usize * SectionHeader::size_with(&ctx);
        // if count == 0 as usize {
        //     // Zero count means either no section headers if offset is also zero (checked
        //     // above), or the number of section headers overflows SHN_LORESERVE, in which
        //     // case the count is stored in the sh_size field of the null section header.
        //     count = empty_sh.sh_size as usize;
        // }

        // /let null_sec_hdr =
        inode.read_at(
            elf_hdr.e_shoff as usize,
            &mut elf_buf[elf_hdr.e_shoff as usize..(elf_hdr.e_shoff as usize + section_hdrs_size)],
        );
        Ok((elf_buf, elf_hdr))
    }
}

pub trait ProgramHeaderExt<'a> {
    fn loadable(&self) -> bool;
    fn is_interpreter(&self) -> bool;
    fn validate(&self) -> Result<()>;
    fn get_content(&self, elf_file: &ElfFile<'a>) -> &'a [u8];
}

impl<'a> ProgramHeaderExt<'a> for ProgramHeader {
    /// Is the segment loadable?
    fn loadable(&self) -> bool {
        let type_ = self.p_type;
        type_ == goblin::elf::program_header::PT_LOAD
    }

    fn is_interpreter(&self) -> bool {
        let type_ = self.p_type;
        type_ == goblin::elf::program_header::PT_INTERP
    }

    fn get_content(&self, elf_file: &ElfFile<'a>) -> &'a [u8] {
        //self.get_data(&elf_file.elf_inner).unwrap()
        let file_range = self.file_range();
        &elf_file.elf_buf[file_range.start..file_range.end]
    }

    /// Do some basic sanity checks in case the ELF is corrupted somehow
    fn validate(&self) -> Result<()> {
        if !self.p_align.is_power_of_two() {
            return_errno!(EINVAL, "invalid memory alignment");
        }

        if self.p_memsz < self.p_filesz {
            return_errno!(EINVAL, "memory size must be no less than file size");
        }
        Ok(())
    }
}
