extern crate capstone;
extern crate macho;

use capstone::prelude::*;
use std::env;
use std::fs;
use std::io::Read;
use std::convert::TryInto;
use capstone::InsnGroupType::*;
use capstone::arch::x86::X86Insn::*;

#[derive(Debug)]
struct Gadget {
    instrs: String,
    addr: u64
}


fn is_cflow_group(g: u32) -> bool {
    g == CS_GRP_JUMP || g == CS_GRP_CALL
        || g == CS_GRP_RET || g == CS_GRP_IRET
}


fn is_cflow_ins(detail: &InsnDetail) -> bool {
    for i in detail.groups() {
        if is_cflow_group(i.0 as u32) {
            return true
        }
    }
    false
}


fn is_ret_ins(id: u32) -> bool {
    id == X86_INS_RET as u32
}


fn update_len(len: &mut usize) -> usize {
    *len += 1;
    *len
}


fn find_gadgets_at_root(text: &[u8], root: u64, vma: u64, cs: &Capstone,
                        gadgets: &mut Vec<Gadget>) {
    let (mut len, mut n): (usize, usize);
    let (mut pc, mut offset, mut addr): (u64, u64, u64);
    let mut gadget_string: String;

    let max_gadget_len: u64 = 5;
    let max_ins_bytes: u64 = 15;
    let root_offset: u64 = max_gadget_len * max_ins_bytes;

    let mut a: u64 = root - 1;
    while (a >= root - root_offset) && a >= vma {

        addr = a;
        offset = addr - vma;
        pc = offset;
        n = (text.len() as u64 - offset).try_into().unwrap();
        len = 0;
        gadget_string = String::from("");
        let insns = cs.disasm_all(&text[pc as usize..(pc as usize +n) as usize]
                                  , addr).expect("Disassembly failure");

        for i in insns.iter() {

            let ins_str: String = String::from(format!("{}", i));
            let gadget_ins = ins_str.split(": ").collect::<Vec<&str>>()[1];
            let detail: InsnDetail = cs.insn_detail(&i)
                .expect("Failed to get insn detail");

            if i.id().0 == X86_INS_INVALID as u32 || i.bytes().len() == 0 {
                break;
            } else if i.address() > root {
                break;
            } else if is_cflow_ins(&detail) && !is_ret_ins(i.id().0){
                break;
            } else if update_len(&mut len) > max_gadget_len as usize {
                break;
            }

            gadget_string.push(' ');
            gadget_string.push_str(gadget_ins);

            if i.address() == root {
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


fn main() {
    let mut cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .build()
        .expect("Failed to create capstone handle");

    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <file>", args[0]);
        return;
    }

    cs.set_detail(true).unwrap();

    let mut fh = fs::File::open(&args[1]).expect("Failed to open file");
    let mut buf: Vec<u8> = Vec::new();
    let _ = fh.read_to_end(&mut buf);

    let mut gadgets: Vec<Gadget> = Vec::new();
    let x86_opc_ret: u8 = 0xc3;

    let header = macho::MachObject::parse(&buf[..])
        .expect("Failed to parse header");

    for segment in header.segments {
        for section in segment.sections {
            if section.segname == "__TEXT" && section.sectname == "__text" {

                let text = &buf[section.offset as usize
                .. (u64::from(section.offset) + section.size) as usize];

                for i in 0 as usize..section.size as usize {
                    if text[i] == x86_opc_ret {
                        find_gadgets_at_root(text, section.addr + i as u64,
                                             section.addr as u64, &cs,
                                             &mut gadgets);
                    }
                }
            }
        }
    }

    for i in gadgets.iter() {
        println!("0x{:016x}: {}", i.addr, i.instrs);
    }
}
