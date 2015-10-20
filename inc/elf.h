#ifndef JOS_INC_ELF_H
#define JOS_INC_ELF_H

#define ELF_MAGIC 0x464C457FU	/* "\x7FELF" in little endian */

struct Elf {
	uint32_t e_magic;	// must equal ELF_MAGIC
	uint8_t e_elf[12];      
	uint16_t e_type;        // specifies whether the object is relocatablem executable, shared, or core, respectively
	uint16_t e_machine;     // specifies specific target instruction set architecture (ex. 0x03 = x86)
	uint32_t e_version;     // set to 1 for the original version of ELF
	uint32_t e_entry;       // entry point for the process to start executing
	uint32_t e_phoff;       // e_phoff points to the start of the program header table
	uint32_t e_shoff;       // points to the start of the section header table 
	uint32_t e_flags;       // flags dependent of target architecture
	uint16_t e_ehsize;      // size of this header
	uint16_t e_phentsize;   // size of program header table entry
	uint16_t e_phnum;       // contains number of entries in the program header table
	uint16_t e_shentsize;   // contains size of the section header table entry
	uint16_t e_shnum;       // contains the number of entries in the section header table
	uint16_t e_shstrndx;    // contains the section header entry that contains the section names
};

struct Proghdr {
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_va;
	uint32_t p_pa;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
};

struct Secthdr {
	uint32_t sh_name;
	uint32_t sh_type;
	uint32_t sh_flags;
	uint32_t sh_addr;
	uint32_t sh_offset;
	uint32_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint32_t sh_addralign;
	uint32_t sh_entsize;
};

// Values for Proghdr::p_type
#define ELF_PROG_LOAD		1

// Flag bits for Proghdr::p_flags
#define ELF_PROG_FLAG_EXEC	1
#define ELF_PROG_FLAG_WRITE	2
#define ELF_PROG_FLAG_READ	4

// Values for Secthdr::sh_type
#define ELF_SHT_NULL		0
#define ELF_SHT_PROGBITS	1
#define ELF_SHT_SYMTAB		2
#define ELF_SHT_STRTAB		3

// Values for Secthdr::sh_name
#define ELF_SHN_UNDEF		0

#endif /* !JOS_INC_ELF_H */
