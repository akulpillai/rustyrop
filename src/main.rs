extern crate capstone;
extern crate macho;
extern crate elf;

use capstone::prelude::*;
use std::io;
use std::env;
use std::fs;
use std::io::Read;
use std::error::Error;
use std::convert::TryInto;
use std::path::PathBuf;

use capstone::InsnGroupType::*;
use capstone::arch::x86::X86Insn::*;

use colored::*;

#[derive(Debug)]
struct Gadget {
    instrs: String,
    addr: u64,
}

struct TextSection {
    addr: u64,
    size: usize,
    data: Vec<u8>,
}

enum BinFormat {
    MachO32,
    MachO64,
    ELF,
}

struct Amd64<'a> {
    section: &'a TextSection,
}

// enum Arch {
//     Amd64,
//     X86,
//     ARM,
//     ARM64
// }

fn find_binary_format(fname: &str) -> Result<BinFormat, io::Error> {
    let macho32_magic = [0xfe, 0xed, 0xfa, 0xce];
    let macho64_magic = [0xfe, 0xed, 0xfa, 0xcf];

    let elf_magic = [0x7f, 0x45, 0x4c, 0x46];

    let mut fh = fs::File::open(fname)?;
    let mut magic : [u8; 4] = [0; 4];
    fh.read_exact(&mut magic).unwrap();

    if magic == macho64_magic || magic.iter().eq(macho64_magic.iter().rev()) {
        return Ok(BinFormat::MachO64)
    }

    if magic == macho32_magic || magic.iter().eq(macho32_magic.iter().rev()) {
        return Ok(BinFormat::MachO32)
    }

    if magic == elf_magic {
        return Ok(BinFormat::ELF)
    }

    Err(io::Error::new(io::ErrorKind::InvalidData,
                       "Binary format not recognized"))
}

fn get_text_section_macho(fname: &str) -> Result<TextSection, io::Error> {
    let mut fh = fs::File::open(fname)?;
    let mut buf: Vec<u8> = Vec::new();
    let _ = fh.read_to_end(&mut buf);

    let header = macho::MachObject::parse(&buf[..])
        .expect("Failed to parse header");

    for segment in header.segments {
        for section in segment.sections {
            if section.segname == "__TEXT" && section.sectname == "__text" {
                let text = &buf[section.offset as usize
                    .. (u64::from(section.offset) + section.size) as usize];
                return Ok( TextSection {
                    addr: section.addr,
                    size: section.size as usize,
                    data: text.to_vec()
                })
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "Text section not found"))
}

fn get_text_section_elf(fname: &str) -> Result<TextSection, io::Error> {
    let path = PathBuf::from(fname);
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    let section = match file.get_section(".text") {
        Some(s) => s,
        None => panic!("Failed to look up .text section"),
    };

    Ok(TextSection {
        addr: section.shdr.addr as u64,
        size: section.shdr.size as usize,
        data: section.data.to_vec()
    })
}

impl Amd64<'_> {
    fn is_cflow_group(&self, g: u32) -> bool {
        g == CS_GRP_JUMP || g == CS_GRP_CALL ||
            g == CS_GRP_RET || g == CS_GRP_IRET
    }

    fn is_cflow_ins(&self, detail: &InsnDetail) -> bool {
        for i in detail.groups() {
            if self.is_cflow_group(i.0 as u32) {
                return true
            }
        }
        false
    }

    fn is_ret_ins(&self, id: u32) -> bool {
        id == X86_INS_RET as u32
    }

    fn find_gadgets_at_root(&self,root: u64, vma: u64,
                            cs: &Capstone, gadgets: &mut Vec<Gadget>) {
        let (mut len, mut n): (usize, usize);
        let (mut offset, mut addr): (u64, u64);
        let mut gadget_string: String;

        let max_gadget_len: u64 = 10;
        let max_ins_bytes: u64 = 15;
        let root_offset: u64 = max_gadget_len * max_ins_bytes;

        let mut a: u64 = root - 1;
        while (a >= root - root_offset) && a >= vma {
            addr = a;
            offset = addr - vma;
            n = (self.section.data.len() as u64 - offset).try_into().unwrap();
            len = 0;
            gadget_string = String::from("");
            let mut prev_ins_size = 0;
            while prev_ins_size < n {
                let insns = cs.disasm_count(
                    &self.section.data[(offset as usize + prev_ins_size)
                                       ..(offset as usize + n)],
                    addr, 1)
                    .expect("Disassembly failure");

                if insns.is_empty() {
                    break;
                }

                let i = insns.iter().next().unwrap();
                prev_ins_size += i.bytes().len();

                let ins_str: String = String::from(format!("{}", i));
                let gadget_ins = ins_str.split(": ").collect::<Vec<&str>>()[1];
                let detail: InsnDetail = cs.insn_detail(&i)
                    .expect("Failed to get instruction details");

                if i.id().0 == X86_INS_INVALID as u32 || i.bytes().len() == 0 {
                    break;
                } else if i.address() > root {
                    break;
                } else if self.is_cflow_ins(&detail) &&
                    !self.is_ret_ins(i.id().0)
                {
                    break;
                } else {
                    len += 1;
                    if len > max_gadget_len as usize {
                        break;
                    }
                }

                gadget_string.push(' ');
                gadget_string.push_str(gadget_ins);

                // disasm_count() returns incorrect addresses when used like
                // this so we add prev_ins_size to correct the offset
                if i.address() + prev_ins_size as u64 == root {
                    gadget_string.push_str("; ret");
                    gadgets.push( Gadget {
                        instrs: gadget_string,
                        addr: a
                    }
                    );
                    break;
                }
                gadget_string.push(';');
            }
            a -= 1;
        }
    }

    fn init_capstone(&self) -> Result<Capstone, Box<dyn Error>> {
        let mut cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build()
            .expect("Failed to create capstone handle");
        cs.set_detail(true).unwrap();

        Ok(cs)
    }

    fn scan_gadgets(&self)
                    -> Result<Vec<Gadget>, io::Error> {
        let cs = self.init_capstone().unwrap();

        let mut gadgets: Vec<Gadget> = Vec::new();
        let x86_opc_ret: u8 = 0xc3;


        for i in 0 as usize..self.section.size {
            if self.section.data[i] == x86_opc_ret {
                self.find_gadgets_at_root(self.section.addr + i as u64,
                                          self.section.addr as u64, &cs,
                                          &mut gadgets);
            }
        }
        Ok(gadgets)
    }

}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <file>", args[0]);
        return;
    }

    let path = &args[1];

    let file_format = find_binary_format(path).unwrap();

    let section = match file_format {
        BinFormat::MachO64 => {
            get_text_section_macho(path).unwrap()
        },
        BinFormat::MachO32 => {
            unimplemented!();
        },
        BinFormat::ELF => {
            get_text_section_elf(path).unwrap()
        }
    };

    let amd64 = Amd64 {
        section: &section,
    };

    let gadgets = amd64.scan_gadgets().unwrap();

    for i in gadgets.iter() {
        println!("{}: {}", String::from(format!("{:#018x}",i.addr)).yellow(),
                 i.instrs.blue());
    }
    println!("Found {} Gadgets", gadgets.len());
}
