/*-
 * Copyright (c) 1998 John D. Polstra.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/sys/elf_common.h,v 1.37 2010/11/23 12:51:08 kib Exp $
 */

#ifndef _SYS_ELF_COMMON_H_
#define _SYS_ELF_COMMON_H_

#ifndef _SYS_TYPES_H_
#include <sys/types.h>
#endif

/*
 * ELF definitions that are independent of architecture or word size.
 */

/*
 * Note header.  The ".note" section contains an array of notes.  Each
 * begins with this header, aligned to a word boundary.  Immediately
 * following the note header is n_namesz bytes of name, padded to the
 * next word boundary.  Then comes n_descsz bytes of descriptor, again
 * padded to a word boundary.  The values of n_namesz and n_descsz do
 * not include the padding.
 */

typedef struct {
	u_int32_t	n_namesz;	/* Length of name. */
	u_int32_t	n_descsz;	/* Length of descriptor. */
	u_int32_t	n_type;		/* Type of this note. */
} Elf_Note;

/* Indexes into the e_ident array.  Keep synced with 
   http://www.sco.com/developers/gabi/latest/ch4.eheader.html */
#define EI_MAG0		0	/* Magic number, byte 0. */
#define EI_MAG1		1	/* Magic number, byte 1. */
#define EI_MAG2		2	/* Magic number, byte 2. */
#define EI_MAG3		3	/* Magic number, byte 3. */
#define EI_CLASS	4	/* Class of machine. */
#define EI_DATA		5	/* Data format. */
#define EI_VERSION	6	/* ELF format version. */
#define EI_OSABI	7	/* Operating system / ABI identification */
#define EI_ABIVERSION	8	/* ABI version */
#define EI_PAD		9	/* Start of padding (per SVR4 ABI). */
#define EI_NIDENT	16	/* Size of e_ident array. */

/* Values for the magic number bytes. */
#define ELFMAG0		0x7f
#define ELFMAG1		'E'
#define ELFMAG2		'L'
#define ELFMAG3		'F'
#define ELFMAG		"\177ELF"	/* magic string */
#define SELFMAG		4		/* magic string size */

/* Values for e_ident[EI_VERSION] and e_version. */
#define EV_NONE		0
#define EV_CURRENT	1

/* Values for e_ident[EI_CLASS]. */
#define ELFCLASSNONE	0	/* Unknown class. */
#define ELFCLASS32	1	/* 32-bit architecture. */
#define ELFCLASS64	2	/* 64-bit architecture. */

/* Values for e_ident[EI_DATA]. */
#define ELFDATANONE	0	/* Unknown data format. */
#define ELFDATA2LSB	1	/* 2's complement little-endian. */
#define ELFDATA2MSB	2	/* 2's complement big-endian. */

/* Values for e_ident[EI_OSABI]. */
#define ELFOSABI_NONE		0	/* UNIX System V ABI */
#define ELFOSABI_HPUX		1	/* HP-UX operating system */
#define ELFOSABI_NETBSD		2	/* NetBSD */
#define ELFOSABI_LINUX		3	/* GNU/Linux */
#define ELFOSABI_HURD		4	/* GNU/Hurd */
#define ELFOSABI_86OPEN		5	/* 86Open common IA32 ABI */
#define ELFOSABI_SOLARIS	6	/* Solaris */
#define ELFOSABI_AIX		7	/* AIX */
#define ELFOSABI_IRIX		8	/* IRIX */
#define ELFOSABI_FREEBSD	9	/* FreeBSD */
#define ELFOSABI_TRU64		10	/* TRU64 UNIX */
#define ELFOSABI_MODESTO	11	/* Novell Modesto */
#define ELFOSABI_OPENBSD	12	/* OpenBSD */
#define ELFOSABI_OPENVMS	13	/* Open VMS */
#define ELFOSABI_NSK		14	/* HP Non-Stop Kernel */
#define ELFOSABI_AROS		15	/* Amiga Research OS */
#define ELFOSABI_ARM		97	/* ARM */
#define ELFOSABI_STANDALONE	255	/* Standalone (embedded) application */

#define ELFOSABI_SYSV		ELFOSABI_NONE	/* symbol used in old spec */
#define ELFOSABI_MONTEREY	ELFOSABI_AIX	/* Monterey */

/* e_ident */
#define IS_ELF(ehdr)	((ehdr).e_ident[EI_MAG0] == ELFMAG0 && \
			 (ehdr).e_ident[EI_MAG1] == ELFMAG1 && \
			 (ehdr).e_ident[EI_MAG2] == ELFMAG2 && \
			 (ehdr).e_ident[EI_MAG3] == ELFMAG3)

/* Values for e_type. */
#define ET_NONE		0	/* Unknown type. */
#define ET_REL		1	/* Relocatable. */
#define ET_EXEC		2	/* Executable. */
#define ET_DYN		3	/* Shared object. */
#define ET_CORE		4	/* Core file. */
#define ET_LOOS		0xfe00	/* First operating system specific. */
#define ET_HIOS		0xfeff	/* Last operating system-specific. */
#define ET_LOPROC	0xff00	/* First processor-specific. */
#define ET_HIPROC	0xffff	/* Last processor-specific. */

/* Values for e_machine. */
#define EM_NONE		0	/* Unknown machine. */
#define EM_M32		1	/* AT&T WE32100. */
#define EM_SPARC	2	/* Sun SPARC. */
#define EM_386		3	/* Intel i386. */
#define EM_68K		4	/* Motorola 68000. */
#define EM_88K		5	/* Motorola 88000. */
#define EM_860		7	/* Intel i860. */
#define EM_MIPS		8	/* MIPS R3000 Big-Endian only. */
#define EM_S370		9	/* IBM System/370. */
#define EM_MIPS_RS3_LE	10	/* MIPS R3000 Little-Endian. */
#define EM_PARISC	15	/* HP PA-RISC. */
#define EM_VPP500	17	/* Fujitsu VPP500. */
#define EM_SPARC32PLUS	18	/* SPARC v8plus. */
#define EM_960		19	/* Intel 80960. */
#define EM_PPC		20	/* PowerPC 32-bit. */
#define EM_PPC64	21	/* PowerPC 64-bit. */
#define EM_S390		22	/* IBM System/390. */
#define EM_V800		36	/* NEC V800. */
#define EM_FR20		37	/* Fujitsu FR20. */
#define EM_RH32		38	/* TRW RH-32. */
#define EM_RCE		39	/* Motorola RCE. */
#define EM_ARM		40	/* ARM. */
#define EM_SH		42	/* Hitachi SH. */
#define EM_SPARCV9	43	/* SPARC v9 64-bit. */
#define EM_TRICORE	44	/* Siemens TriCore embedded processor. */
#define EM_ARC		45	/* Argonaut RISC Core. */
#define EM_H8_300	46	/* Hitachi H8/300. */
#define EM_H8_300H	47	/* Hitachi H8/300H. */
#define EM_H8S		48	/* Hitachi H8S. */
#define EM_H8_500	49	/* Hitachi H8/500. */
#define EM_IA_64	50	/* Intel IA-64 Processor. */
#define EM_MIPS_X	51	/* Stanford MIPS-X. */
#define EM_COLDFIRE	52	/* Motorola ColdFire. */
#define EM_68HC12	53	/* Motorola M68HC12. */
#define EM_MMA		54	/* Fujitsu MMA. */
#define EM_PCP		55	/* Siemens PCP. */
#define EM_NCPU		56	/* Sony nCPU. */
#define EM_NDR1		57	/* Denso NDR1 microprocessor. */
#define EM_STARCORE	58	/* Motorola Star*Core processor. */
#define EM_ME16		59	/* Toyota ME16 processor. */
#define EM_ST100	60	/* STMicroelectronics ST100 processor. */
#define EM_TINYJ	61	/* Advanced Logic Corp. TinyJ processor. */
#define EM_X86_64	62	/* Advanced Micro Devices x86-64 */
#define EM_PDSP		63	/* Sony DSP Processor */
#define EM_FX66		66	/* Siemens FX66 microcontroller */
#define EM_ST9PLUS	67	/* STMicroelectronics ST9+ 8/16 mc */
#define EM_ST7		68	/* STmicroelectronics ST7 8 bit mc */
#define EM_68HC16	69	/* Motorola MC68HC16 microcontroller */
#define EM_68HC11	70	/* Motorola MC68HC11 microcontroller */
#define EM_68HC08	71	/* Motorola MC68HC08 microcontroller */
#define EM_68HC05	72	/* Motorola MC68HC05 microcontroller */
#define EM_SVX		73	/* Silicon Graphics SVx */
#define EM_ST19		74	/* STMicroelectronics ST19 8 bit mc */
#define EM_VAX		75	/* Digital VAX */
#define EM_CRIS		76	/* Axis Comm. 32-bit embedded processor */
#define EM_JAVELIN	77	/* Infineon Tech. 32-bit embedded processor */
#define EM_FIREPATH	78	/* Element 14 64-bit DSP Processor */
#define EM_ZSP		79	/* LSI Logic 16-bit DSP Processor */
#define EM_MMIX		80	/* Donald Knuth's educational 64-bit proc */
#define EM_HUANY	81	/* Harvard Uni. machine-independent obj files */
#define EM_PRISM	82	/* SiTera Prism */
#define EM_AVR		83	/* Atmel AVR 8-bit microcontroller */
#define EM_FR30		84	/* Fujitsu FR30 */
#define EM_D10V		85	/* Mitsubishi D10V */
#define EM_D30V		86	/* Mitsubishi D30V */
#define EM_V850		87	/* NEC v850 */
#define EM_M32R		88	/* Mitsubishi M32R */
#define EM_MN10300	89	/* Matsushita MN10300 */
#define EM_MN10200	90	/* Matsushita MN10200 */
#define EM_PJ		91	/* picoJava */
#define EM_OPENRISC	92	/* OpenRISC 32-bit embedded processor */
#define EM_ARC_A5	93	/* ARC Cores Tangent-A5 */
#define EM_XTENSA	94	/* Tensilica Xtensa Architecture */
#define EM_VIDEOCORE	95	/* Alphamosaic VideoCore processor */
#define EM_TMM_GPP	96	/* Thompson Multimedia General Purpose Proc  */
#define EM_NS32K	97	/* National Semiconductor 32000 series */
#define EM_TPC		98	/* Tenor Network TPC processor */
#define EM_SNP1K	99	/* Trebia SNP 1000 processor */
#define EM_ST200	100	/* STMicroelectronics ST200 microcontroller */
#define EM_IP2K		101	/* Ubicom IP2xxx microcontroller family */
#define EM_MAX		102	/* MAX Processor */
#define EM_CR		103	/* NatSemi CompactRISC microprocessor */
#define EM_F2MC16	104	/* Fujitsu F2MC16 */
#define EM_MSP430	105	/* TI embedded microcontroller msp430 */
#define EM_BLACKFIN 	106	/* Analog Devices Blackfin (DSP) processor */
#define EM_SE_C33 	107	/* S1C33 Family of Seiko Epson processors */
#define EM_SEP		108	/* Sharp embedded microprocessor */
#define EM_ARCA		109	/* Arca RISC Microprocessor */
#define EM_UNICORE	110	/* Microprocessor series from PKU-Unity Ltd. */
				/* and MPRC of Peking University */

/* Non-standard or deprecated. */
#define EM_486		6	/* Intel i486. */
#define EM_MIPS_RS4_BE	10	/* MIPS R4000 Big-Endian */
#define EM_ALPHA_STD	41	/* Digital Alpha (standard value). */

#define EM_NUM		111

/* Special section indexes. */
#define SHN_UNDEF	     0		/* Undefined, missing, irrelevant. */
#define SHN_LORESERVE	0xff00		/* First of reserved range. */
#define SHN_LOPROC	0xff00		/* First processor-specific. */
#define SHN_HIPROC	0xff1f		/* Last processor-specific. */
#define SHN_LOOS	0xff20		/* First operating system-specific. */
#define SHN_HIOS	0xff3f		/* Last operating system-specific. */
#define SHN_ABS		0xfff1		/* Absolute values. */
#define SHN_COMMON	0xfff2		/* Common data. */
#define SHN_XINDEX	0xffff		/* Escape -- index stored elsewhere. */
#define SHN_HIRESERVE	0xffff		/* Last of reserved range. */

/* sh_type */
#define SHT_NULL		0	/* inactive */
#define SHT_PROGBITS		1	/* program defined information */
#define SHT_SYMTAB		2	/* symbol table section */
#define SHT_STRTAB		3	/* string table section */
#define SHT_RELA		4	/* relocation section with addends */
#define SHT_HASH		5	/* symbol hash table section */
#define SHT_DYNAMIC		6	/* dynamic section */
#define SHT_NOTE		7	/* note section */
#define SHT_NOBITS		8	/* no space section */
#define SHT_REL			9	/* relocation section - no addends */
#define SHT_SHLIB		10	/* reserved - purpose unknown */
#define SHT_DYNSYM		11	/* dynamic symbol table section */
#define SHT_INIT_ARRAY		14	/* Initialization function pointers. */
#define SHT_FINI_ARRAY		15	/* Termination function pointers. */
#define SHT_PREINIT_ARRAY	16	/* Pre-initialization function ptrs. */
#define SHT_GROUP		17	/* Section group. */
#define SHT_SYMTAB_SHNDX	18	/* Section indexes (see SHN_XINDEX). */

#define SHT_NUM			19	/* number of section types */

#define SHT_LOOS		0x60000000	/* First of OS specific semantics */
#define SHT_HIOS		0x6fffffff	/* Last of OS specific semantics */
#define SHT_LOPROC		0x70000000	/* reserved range for processor */
#define SHT_AMD64_UNWIND	0x70000001	/* unwind information */
#define SHT_HIPROC		0x7fffffff	/* specific section header types */
#define SHT_LOUSER		0x80000000	/* reserved range for application */
#define SHT_HIUSER		0xffffffff	/* specific indexes */

/* Flags for sh_flags. */
#define SHF_WRITE		0x1	/* Section contains writable data. */
#define SHF_ALLOC		0x2	/* Section occupies memory. */
#define SHF_EXECINSTR		0x4	/* Section contains instructions. */
#define SHF_MERGE		0x10	/* Section may be merged. */
#define SHF_STRINGS		0x20	/* Section contains strings. */
#define SHF_INFO_LINK		0x40	/* sh_info holds section index. */
#define SHF_LINK_ORDER		0x80	/* Special ordering requirements. */
#define SHF_OS_NONCONFORMING	0x100	/* OS-specific processing required. */
#define SHF_GROUP		0x200	/* Member of section group. */
#define SHF_TLS			0x400	/* Section contains TLS data. */
#define SHF_MASKOS	0x0ff00000	/* OS-specific semantics. */
#define SHF_MASKPROC	0xf0000000	/* Processor-specific semantics. */

/* Section group flags. */
#define GRP_COMDAT	0x1		/* Group is a COMDAT. */
#define GRP_MASKOS	0x0ff00000	/* Reserved for OS-specific. */
#define GRP_MASKPROC	0xf0000000	/* Reserved for processor-specific. */

/* Values for p_type. */
#define PT_NULL		0	/* Unused entry. */
#define PT_LOAD		1	/* Loadable segment. */
#define PT_DYNAMIC	2	/* Dynamic linking information segment. */
#define PT_INTERP	3	/* Pathname of interpreter. */
#define PT_NOTE		4	/* Auxiliary information. */
#define PT_SHLIB	5	/* Reserved (not used). */
#define PT_PHDR		6	/* Location of program header itself. */
#define PT_TLS		7	/* Thread local storage segment */

#define PT_COUNT	8	/* Number of defined p_type values. */

#define PT_LOOS		0x60000000	/* First OS-specific. */
#define PT_GNU_EH_FRAME	0x6474e550
#define PT_GNU_STACK	0x6474e551
#define PT_HIOS		0x6fffffff	/* Last OS-specific. */
#define PT_LOPROC	0x70000000	/* First processor-specific type. */
#define PT_HIPROC	0x7fffffff	/* Last processor-specific type. */

/* Values for p_flags. */
#define PF_X		0x1		/* Executable. */
#define PF_W		0x2		/* Writable. */
#define PF_R		0x4		/* Readable. */
#define PF_MASKOS	0x0ff00000	/* Operating system-specific. */
#define PF_MASKPROC	0xf0000000	/* Processor-specific. */

/* Values for d_tag. */
#define DT_NULL		0	/* Terminating entry. */
#define DT_NEEDED	1	/* String table offset of a needed shared
				   library. */
#define DT_PLTRELSZ	2	/* Total size in bytes of PLT relocations. */
#define DT_PLTGOT	3	/* Processor-dependent address. */
#define DT_HASH		4	/* Address of symbol hash table. */
#define DT_STRTAB	5	/* Address of string table. */
#define DT_SYMTAB	6	/* Address of symbol table. */
#define DT_RELA		7	/* Address of ElfNN_Rela relocations. */
#define DT_RELASZ	8	/* Total size of ElfNN_Rela relocations. */
#define DT_RELAENT	9	/* Size of each ElfNN_Rela relocation entry. */
#define DT_STRSZ	10	/* Size of string table. */
#define DT_SYMENT	11	/* Size of each symbol table entry. */
#define DT_INIT		12	/* Address of initialization function. */
#define DT_FINI		13	/* Address of finalization function. */
#define DT_SONAME	14	/* String table offset of shared object
				   name. */
#define DT_RPATH	15	/* String table offset of library path. [sup] */
#define DT_SYMBOLIC	16	/* Indicates "symbolic" linking. [sup] */
#define DT_REL		17	/* Address of ElfNN_Rel relocations. */
#define DT_RELSZ	18	/* Total size of ElfNN_Rel relocations. */
#define DT_RELENT	19	/* Size of each ElfNN_Rel relocation. */
#define DT_PLTREL	20	/* Type of relocation used for PLT. */
#define DT_DEBUG	21	/* Reserved (not used). */
#define DT_TEXTREL	22	/* Indicates there may be relocations in
				   non-writable segments. [sup] */
#define DT_JMPREL	23	/* Address of PLT relocations. */
#define DT_BIND_NOW	24	/* [sup] */
#define DT_INIT_ARRAY	25	/* Address of the array of pointers to
				   initialization functions */
#define DT_FINI_ARRAY	26	/* Address of the array of pointers to
				   termination functions */
#define DT_INIT_ARRAYSZ	27	/* Size in bytes of the array of
				   initialization functions. */
#define DT_FINI_ARRAYSZ	28	/* Size in bytes of the array of
				   terminationfunctions. */
#define DT_RUNPATH	29	/* String table offset of a null-terminated
				   library search path string. */
#define DT_FLAGS	30	/* Object specific flag values. */
#define DT_ENCODING	32	/* Values greater than or equal to DT_ENCODING
				   and less than DT_LOOS follow the rules for
				   the interpretation of the d_un union
				   as follows: even == 'd_ptr', odd == 'd_val'
				   or none */
#define DT_PREINIT_ARRAY 32	/* Address of the array of pointers to
				   pre-initialization functions. */
#define DT_PREINIT_ARRAYSZ 33	/* Size in bytes of the array of
				   pre-initialization functions. */

#define DT_COUNT	34	/* Number of defined d_tag values. */

#define DT_LOOS		0x6000000d	/* First OS-specific */
#define DT_HIOS		0x6fff0000	/* Last OS-specific */

/*
 * DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
 * Dyn.d_un.d_val field of the Elf*_Dyn structure.
 */
#define DT_VALRNGLO	0x6ffffd00
#define DT_CHECKSUM	0x6ffffdf8	/* elf checksum */
#define DT_PLTPADSZ	0x6ffffdf9	/* pltpadding size */
#define DT_MOVEENT	0x6ffffdfa	/* move table entry size */
#define DT_MOVESZ	0x6ffffdfb	/* move table size */
#define DT_FEATURE_1	0x6ffffdfc	/* feature holder */
#define DT_POSFLAG_1	0x6ffffdfd	/* flags for DT_* entries, effecting */
					/*	the following DT_* entry. */
					/*	See DF_P1_* definitions */
#define DT_SYMINSZ	0x6ffffdfe	/* syminfo table size (in bytes) */
#define DT_SYMINENT	0x6ffffdff	/* syminfo entry size (in bytes) */
#define DT_VALRNGHI	0x6ffffdff

/*
 * DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
 * Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
 *
 * If any adjustment is made to the ELF object after it has been
 * built, these entries will need to be adjusted.
 */
#define DT_ADDRRNGLO	0x6ffffe00
#define DT_GNU_HASH	0x6ffffef5	/* GNU-style hash table */
#define DT_CONFIG	0x6ffffefa	/* configuration information */
#define DT_DEPAUDIT	0x6ffffefb	/* dependency auditing */
#define DT_AUDIT	0x6ffffefc	/* object auditing */
#define DT_PLTPAD	0x6ffffefd	/* pltpadding (sparcv9) */
#define DT_MOVETAB	0x6ffffefe	/* move table */
#define DT_SYMINFO	0x6ffffeff	/* syminfo table */
#define DT_ADDRRNGHI	0x6ffffeff

#define DT_VERSYM	0x6ffffff0	/* Address of versym section. */
#define DT_RELACOUNT	0x6ffffff9	/* number of RELATIVE relocations */
#define DT_RELCOUNT	0x6ffffffa	/* number of RELATIVE relocations */
#define DT_FLAGS_1	0x6ffffffb	/* state flags - see DF_1_* defs */
#define DT_VERDEF	0x6ffffffc	/* Address of verdef section. */
#define DT_VERDEFNUM	0x6ffffffd	/* Number of elems in verdef section */
#define DT_VERNEED	0x6ffffffe	/* Address of verneed section. */
#define DT_VERNEEDNUM	0x6fffffff	/* Number of elems in verneed section */

#define DT_LOPROC	0x70000000	/* First processor-specific type. */
#define DT_AUXILIARY	0x7ffffffd	/* shared library auxiliary name */
#define DT_USED		0x7ffffffe	/* ignored - same as needed */
#define DT_FILTER	0x7fffffff	/* shared library filter name */
#define DT_HIPROC	0x7fffffff	/* Last processor-specific type. */

/* Values for DT_FLAGS */
#define DF_ORIGIN	0x0001	/* Indicates that the object being loaded may
				   make reference to the $ORIGIN substitution
				   string */
#define DF_SYMBOLIC	0x0002	/* Indicates "symbolic" linking. */
#define DF_TEXTREL	0x0004	/* Indicates there may be relocations in
				   non-writable segments. */
#define DF_BIND_NOW	0x0008	/* Indicates that the dynamic linker should
				   process all relocations for the object
				   containing this entry before transferring
				   control to the program. */
#define DF_STATIC_TLS	0x0010	/* Indicates that the shared object or
				   executable contains code using a static
				   thread-local storage scheme. */

/* Values for DT_FLAGS_1 */
#define DF_1_BIND_NOW	0x00000001	/* Same as DF_BIND_NOW */
#define DF_1_GLOBAL	0x00000002	/* Set the RTLD_GLOBAL for object */
#define DF_1_NODELETE	0x00000008	/* Set the RTLD_NODELETE for object */
#define DF_1_LOADFLTR	0x00000010	/* Immediate loading of filtees */
#define DF_1_NOOPEN	0x00000040	/* Do not allow loading on dlopen() */
#define DF_1_ORIGIN	0x00000080	/* Process $ORIGIN */

/* Values for n_type.  Used in core files. */
#define NT_PRSTATUS	1	/* Process status. */
#define NT_FPREGSET	2	/* Floating point registers. */
#define NT_PRPSINFO	3	/* Process state info. */
#define NT_THRMISC	7	/* Thread miscellaneous info. */

/* Symbol Binding - ELFNN_ST_BIND - st_info */
#define STB_LOCAL	0	/* Local symbol */
#define STB_GLOBAL	1	/* Global symbol */
#define STB_WEAK	2	/* like global - lower precedence */
#define STB_LOOS	10	/* Reserved range for operating system */
#define STB_HIOS	12	/*   specific semantics. */
#define STB_LOPROC	13	/* reserved range for processor */
#define STB_HIPROC	15	/*   specific semantics. */

/* Symbol type - ELFNN_ST_TYPE - st_info */
#define STT_NOTYPE	0	/* Unspecified type. */
#define STT_OBJECT	1	/* Data object. */
#define STT_FUNC	2	/* Function. */
#define STT_SECTION	3	/* Section. */
#define STT_FILE	4	/* Source file. */
#define STT_COMMON	5	/* Uninitialized common block. */
#define STT_TLS		6	/* TLS object. */
#define STT_NUM		7
#define STT_LOOS	10	/* Reserved range for operating system */
#define STT_HIOS	12	/*   specific semantics. */
#define STT_LOPROC	13	/* reserved range for processor */
#define STT_HIPROC	15	/*   specific semantics. */

/* Symbol visibility - ELFNN_ST_VISIBILITY - st_other */
#define STV_DEFAULT	0x0	/* Default visibility (see binding). */
#define STV_INTERNAL	0x1	/* Special meaning in relocatable objects. */
#define STV_HIDDEN	0x2	/* Not visible. */
#define STV_PROTECTED	0x3	/* Visible but not preemptible. */
#define STV_EXPORTED	0x4
#define STV_SINGLETON	0x5
#define STV_ELIMINATE	0x6

/* Special symbol table indexes. */
#define	STN_UNDEF	0	/* Undefined symbol index. */

/* Symbol versioning flags. */
#define VER_DEF_CURRENT	1
#define VER_DEF_IDX(x)	VER_NDX(x)

#define VER_FLG_BASE	0x01
#define VER_FLG_WEAK	0x02

#define VER_NEED_CURRENT	1
#define VER_NEED_WEAK	(1u << 15)
#define VER_NEED_HIDDEN	VER_NDX_HIDDEN
#define VER_NEED_IDX(x)	VER_NDX(x)

#define VER_NDX_LOCAL	0
#define VER_NDX_GLOBAL	1
#define VER_NDX_GIVEN	2

#define VER_NDX_HIDDEN	(1u << 15)
#define VER_NDX(x)	((x) & ~(1u << 15))

#endif /* !_SYS_ELF_COMMON_H_ */
