#![allow(clippy::unreadable_literal, clippy::similar_names)]

extern crate fnv;

use self::fnv::FnvHashMap;

/// ELF header
pub struct Header {
    pub e_width: u8, // 32 or 64
    pub e_class: u8,
    pub e_endian: u8,
    pub e_elf_version: u8,
    pub e_osabi: u8,
    pub e_abi_version: u8,
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// ELF program header
pub struct ProgramHeader {
    _p_type: u32,
    _p_flags: u32,
    _p_offset: u64,
    _p_vaddr: u64,
    _p_paddr: u64,
    _p_filesz: u64,
    _p_memsz: u64,
    _p_align: u64,
}

/// ELF section header
pub struct SectionHeader {
    sh_name: u32,
    pub sh_type: u32,
    _sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    _sh_link: u32,
    _sh_info: u32,
    _sh_addralign: u64,
    _sh_entsize: u64,
}

/// ELF symbol table entry
pub struct SymbolEntry {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

/// ELF file analyzer
pub struct ElfAnalyzer {
    data: Vec<u8>,
}

impl ElfAnalyzer {
    /// Creates a new `ElfAnalyzer`.
    ///
    /// # Arguments
    /// * `data` ELF file content binary
    #[must_use]
    pub const fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Checks if ELF file content is valid
    // @TODO: Validate more precisely
    #[must_use]
    pub fn validate(&self) -> bool {
        // check ELF magic number
        if self.data.len() < 4
            || self.data[0] != 0x7f
            || self.data[1] != 0x45
            || self.data[2] != 0x4c
            || self.data[3] != 0x46
        {
            return false;
        }
        true
    }

    /// Reads ELF header
    /// # Panics
    /// Elf files with unknown `e_class` will panic
    #[must_use]
    pub fn read_header(&self) -> Header {
        let e_class = self.read_byte(4);

        let e_width = match e_class {
            1 => 32,
            2 => 64,
            _ => panic!("Unknown e_class:{e_class:X}"),
        };

        let e_endian = self.read_byte(5);
        let e_elf_version = self.read_byte(6);
        let e_osabi = self.read_byte(7);
        let e_abi_version = self.read_byte(8);

        let mut offset = 0x10;

        let e_type = self.read_halfword(offset);
        offset += 2;

        let e_machine = self.read_halfword(offset);
        offset += 2;

        let e_version = self.read_word(offset);
        offset += 4;

        let e_entry = if e_width == 64 {
            let data = self.read_doubleword(offset);
            offset += 8;
            data
        } else {
            let data = self.read_word(offset);
            offset += 4;
            u64::from(data)
        };

        let e_phoff = if e_width == 64 {
            let data = self.read_doubleword(offset);
            offset += 8;
            data
        } else {
            let data = self.read_word(offset);
            offset += 4;
            u64::from(data)
        };

        let e_shoff = if e_width == 64 {
            let data = self.read_doubleword(offset);
            offset += 8;
            data
        } else {
            let data = self.read_word(offset);
            offset += 4;
            u64::from(data)
        };

        let e_flags = self.read_word(offset);
        offset += 4;

        let e_ehsize = self.read_halfword(offset);
        offset += 2;

        let e_phentsize = self.read_halfword(offset);
        offset += 2;

        let e_phnum = self.read_halfword(offset);
        offset += 2;

        let e_shentsize = self.read_halfword(offset);
        offset += 2;

        let e_shnum = self.read_halfword(offset);
        offset += 2;

        let e_shstrndx = self.read_halfword(offset);
        //offset += 2;

        /*
        println!("ELF:{}", e_width);
        println!("e_endian:{:X}", e_endian);
        println!("e_elf_version:{:X}", e_elf_version);
        println!("e_osabi:{:X}", e_osabi);
        println!("e_abi_version:{:X}", e_abi_version);
        println!("e_type:{:X}", e_type);
        println!("e_machine:{:X}", e_machine);
        println!("e_version:{:X}", e_version);
        println!("e_entry:{:X}", e_entry);
        println!("e_phoff:{:X}", e_phoff);
        println!("e_shoff:{:X}", e_shoff);
        println!("e_flags:{:X}", e_flags);
        println!("e_ehsize:{:X}", e_ehsize);
        println!("e_phentsize:{:X}", e_phentsize);
        println!("e_phnum:{:X}", e_phnum);
        println!("e_shentsize:{:X}", e_shentsize);
        println!("e_shnum:{:X}", e_shnum);
        println!("e_shstrndx:{:X}", e_shstrndx);
        */

        Header {
            e_width,
            e_class,
            e_endian,
            e_elf_version,
            e_osabi,
            e_abi_version,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        }
    }

    /// Reads ELF program headers
    ///
    /// # Arguments
    /// * `header`
    /// # Panics
    ///
    #[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
    #[must_use]
    pub fn _read_program_headers(&self, header: &Header) -> Vec<ProgramHeader> {
        let mut headers = Vec::new();
        let mut offset = header.e_phoff as usize;
        for _i in 0..header.e_phnum {
            let p_type = self.read_word(offset);
            offset += 4;

            let mut p_flags = 0;
            if header.e_width == 64 {
                p_flags = self.read_word(offset);
                offset += 4;
            }

            let p_offset = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            let p_vaddr = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            let p_paddr = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            let p_filesz = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            let p_memsz = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            if header.e_width == 32 {
                p_flags = self.read_word(offset);
                offset += 4;
            }

            let p_align = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            headers.push(ProgramHeader {
                _p_type: p_type,
                _p_flags: p_flags,
                _p_offset: p_offset,
                _p_vaddr: p_vaddr,
                _p_paddr: p_paddr,
                _p_filesz: p_filesz,
                _p_memsz: p_memsz,
                _p_align: p_align,
            });
        }

        headers
    }

    /// Reads ELF section headers
    ///
    /// # Arguments
    /// * `header`
    #[allow(clippy::cast_possible_truncation, clippy::too_many_lines)]
    #[must_use]
    pub fn read_section_headers(&self, header: &Header) -> Vec<SectionHeader> {
        let mut headers = Vec::new();
        let mut offset = header.e_shoff as usize;
        for _i in 0..header.e_shnum {
            let sh_name = self.read_word(offset);
            offset += 4;

            let sh_type = self.read_word(offset);
            offset += 4;

            let sh_flags = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            let sh_addr = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            let sh_offset = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            let sh_size = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            let sh_link = self.read_word(offset);
            offset += 4;

            let sh_info = self.read_word(offset);
            offset += 4;

            let sh_addralign = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            let sh_entsize = match header.e_width {
                64 => {
                    let data = self.read_doubleword(offset);
                    offset += 8;
                    data
                }
                32 => {
                    let data = self.read_word(offset);
                    offset += 4;
                    u64::from(data)
                }
                _ => unreachable!(),
            };

            /*
            println!("");
            println!("Section:{:X}", _i);
            println!("sh_name:{:X}", sh_name);
            println!("sh_type:{:X}", sh_type);
            println!("sh_flags:{:X}", sh_flags);
            println!("sh_addr:{:X}", sh_addr);
            println!("sh_offset:{:X}", sh_offset);
            println!("sh_size:{:X}", sh_size);
            println!("sh_link:{:X}", sh_link);
            println!("sh_info:{:X}", sh_info);
            println!("sh_addralign:{:X}", sh_addralign);
            println!("sh_entsize:{:X}", sh_entsize);
            */

            headers.push(SectionHeader {
                sh_name,
                sh_type,
                _sh_flags: sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                _sh_link: sh_link,
                _sh_info: sh_info,
                _sh_addralign: sh_addralign,
                _sh_entsize: sh_entsize,
            });
        }

        headers
    }

    /// Reads symbol entries of symbol table sections
    ///
    /// # Arguments
    /// * `Terminal`
    /// * `symbol_table_section_headers`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn read_symbol_entries(
        &self,
        header: &Header,
        symbol_table_section_headers: &Vec<&SectionHeader>,
    ) -> Vec<SymbolEntry> {
        let mut entries = Vec::new();
        for h in symbol_table_section_headers {
            let sh_offset = h.sh_offset;
            let sh_size = h.sh_size;

            let mut offset = sh_offset as usize;

            let entry_size = match header.e_width {
                64 => 24,
                32 => 16,
                _ => unreachable!(),
            };

            for _j in 0..(sh_size / entry_size) {
                let st_name;
                let st_info;
                let st_other;
                let st_shndx;
                let st_value;
                let st_size;

                match header.e_width {
                    64 => {
                        st_name = self.read_word(offset);
                        offset += 4;

                        st_info = self.read_byte(offset);
                        offset += 1;

                        st_other = self.read_byte(offset);
                        offset += 1;

                        st_shndx = self.read_halfword(offset);
                        offset += 2;

                        st_value = self.read_doubleword(offset);
                        offset += 8;

                        st_size = self.read_doubleword(offset);
                        offset += 8;
                    }
                    32 => {
                        st_name = self.read_word(offset);
                        offset += 4;

                        st_value = u64::from(self.read_word(offset));
                        offset += 4;

                        st_size = u64::from(self.read_word(offset));
                        offset += 4;

                        st_info = self.read_byte(offset);
                        offset += 1;

                        st_other = self.read_byte(offset);
                        offset += 1;

                        st_shndx = self.read_halfword(offset);
                        offset += 2;
                    }
                    _ => unreachable!(),
                };

                /*
                println!("Symbol: {}", _j);
                println!("st_name: {:X}", st_name);
                println!("st_info: {:X}", st_info);
                println!("st_other: {:X}", _st_other);
                println!("st_shndx: {:X}", _st_shndx);
                println!("st_value: {:X}", st_value);
                println!("st_size: {:X}", _st_size);
                println!("");
                */

                entries.push(SymbolEntry {
                    st_name,
                    st_info,
                    st_other,
                    st_shndx,
                    st_value,
                    st_size,
                });
            }
        }
        entries
    }

    /// Reads strings from a string table section
    ///
    /// # Arguments
    /// * `section_header` The header of the string table section
    /// * `index` Offset in the string table section
    #[allow(clippy::cast_possible_truncation)]
    fn read_strings(&self, section_header: &SectionHeader, index: u64) -> String {
        let sh_offset = section_header.sh_offset;
        let sh_size = section_header.sh_size;
        let mut pos = 0;
        let mut symbol = String::new();
        loop {
            let addr = sh_offset + index + pos;
            if addr >= sh_offset + sh_size {
                break;
            }
            let value = self.read_byte(addr as usize);
            if value == 0 {
                break;
            }
            symbol.push(value as char);
            pos += 1;
        }
        symbol
    }

    /// Creates a symbol - virtual address mapping from symbol entries
    /// and a string table section.
    ///
    /// # Arguments
    /// * `entries` Symbol entries
    /// * `string_table_section_header` The header of the string table section
    #[must_use]
    pub fn create_symbol_map(
        &self,
        entries: &Vec<SymbolEntry>,
        string_table_section_header: &SectionHeader,
    ) -> FnvHashMap<String, u64> {
        let mut map = FnvHashMap::default();
        for st in entries {
            // Stores only function and notype symbol
            if (st.st_info & 0x2) != 0x2 && (st.st_info & 0xf) != 0 {
                continue;
            }

            let symbol = self.read_strings(string_table_section_header, u64::from(st.st_name));

            if !symbol.is_empty() {
                //println!("{} {:0x}", symbol, st.st_value);
                map.insert(symbol, st.st_value);
            }
        }
        map
    }

    /// Finds a program data section whose name is .tohost. If found this method
    /// returns an address of the section.
    ///
    /// # Arguments
    /// * `program_data_section_headers`
    /// * `string_table_section_headers`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn find_tohost_addr(
        &self,
        program_data_section_headers: &Vec<&SectionHeader>,
        string_table_section_headers: &Vec<&SectionHeader>,
    ) -> Option<u64> {
        let tohost_values = [0x2e, 0x74, 0x6f, 0x68, 0x6f, 0x73, 0x74, 0x00]; // ".tohost\null"
        for sh in program_data_section_headers {
            let sh_addr = sh.sh_addr;
            let sh_name = u64::from(sh.sh_name);
            // Find all string sections so far.
            // @TODO: Is there a way to know which string table section
            //        sh_name of program data section points to?
            for sh in string_table_section_headers {
                let sh_offset = sh.sh_offset;
                let sh_size = sh.sh_size;
                let mut found = true;
                for k in 0..tohost_values.len() as u64 {
                    let addr = sh_offset + sh_name + k;
                    if addr >= sh_offset + sh_size
                        || self.read_byte(addr as usize) != tohost_values[k as usize]
                    {
                        found = false;
                        break;
                    }
                }
                if found {
                    return Some(sh_addr);
                }
            }
        }
        None
    }

    /// Reads a byte from ELF file content
    ///
    /// # Arguments
    /// * `offset`
    #[must_use]
    pub fn read_byte(&self, offset: usize) -> u8 {
        self.data[offset]
    }

    /// Reads two bytes from ELF file content
    ///
    /// # Arguments
    /// * `offset`
    fn read_halfword(&self, offset: usize) -> u16 {
        let mut data = 0;
        for i in 0..2 {
            data |= u16::from(self.read_byte(offset + i)) << (8 * i);
        }
        data
    }

    /// Reads four bytes from ELF file content
    ///
    /// # Arguments
    /// * `offset`
    fn read_word(&self, offset: usize) -> u32 {
        let mut data = 0;
        for i in 0..4 {
            data |= u32::from(self.read_byte(offset + i)) << (8 * i);
        }
        data
    }

    /// Reads eight bytes from ELF file content
    ///
    /// # Arguments
    /// * `offset`
    fn read_doubleword(&self, offset: usize) -> u64 {
        let mut data = 0;
        for i in 0..8 {
            data |= u64::from(self.read_byte(offset + i)) << (8 * i);
        }
        data
    }
}
