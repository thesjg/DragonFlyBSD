# $DragonFly: src/share/mk/bsd.cpu.gcc41.mk,v 1.4 2008/01/05 13:37:15 corecode Exp $

# Set default CPU compile flags and baseline CPUTYPE for each arch.  The
# compile flags must support the minimum CPU type for each architecture but
# may tune support for more advanced processors.

.if !defined(CPUTYPE) || empty(CPUTYPE)
_CPUCFLAGS =
. if ${MACHINE_ARCH} == "i386"
MACHINE_CPU = i486
. elif ${MACHINE_ARCH} == "x86_64"
MACHINE_CPU = x86_64 sse2 sse
. endif
.else

# Handle aliases (not documented in make.conf to avoid user confusion
# between e.g. i586 and pentium)

. if ${MACHINE_ARCH} == "i386"
.  if ${CPUTYPE} == "nocona"
CPUTYPE = prescott
.  elif ${CPUTYPE} == "core" || ${CPUTYPE} == "core2"
CPUTYPE = prescott
.  elif ${CPUTYPE} == "p4"
CPUTYPE = pentium4
.  elif ${CPUTYPE} == "p4m"
CPUTYPE = pentium4m
.  elif ${CPUTYPE} == "p3"
CPUTYPE = pentium3
.  elif ${CPUTYPE} == "p3m"
CPUTYPE = pentium3m
.  elif ${CPUTYPE} == "p-m"
CPUTYPE = pentium-m
.  elif ${CPUTYPE} == "p2"
CPUTYPE = pentium2
.  elif ${CPUTYPE} == "i686"
CPUTYPE = pentiumpro
.  elif ${CPUTYPE} == "i586/mmx"
CPUTYPE = pentium-mmx
.  elif ${CPUTYPE} == "i586"
CPUTYPE = pentium
.  elif ${CPUTYPE} == "opteron" || ${CPUTYPE} == "athlon64" || \
     ${CPUTYPE} == "k8"
CPUTYPE = athlon-mp
.  elif ${CPUTYPE} == "k7"
CPUTYPE = athlon
.  endif
. elif ${MACHINE_ARCH} == "x86_64"
.  if ${CPUTYPE} == "prescott" || ${CPUTYPE} == "core2"
CPUTYPE = nocona
.  endif
. endif

###############################################################################
# Logic to set up correct gcc optimization flag.  This must be included
# after /etc/make.conf so it can react to the local value of CPUTYPE
# defined therein.  Consult:
#	http://gcc.gnu.org/onlinedocs/gcc/ARM-Options.html
#	http://gcc.gnu.org/onlinedocs/gcc/IA-64-Options.html
#	http://gcc.gnu.org/onlinedocs/gcc/RS-6000-and-PowerPC-Options.html
#	http://gcc.gnu.org/onlinedocs/gcc/SPARC-Options.html
#	http://gcc.gnu.org/onlinedocs/gcc/i386-and-x86-64-Options.html

. if ${MACHINE_ARCH} == "i386"
.  if ${CPUTYPE} == "crusoe"
_CPUCFLAGS = -march=i686 -falign-functions=0 -falign-jumps=0 -falign-loops=0
.  elif ${CPUTYPE} == "k5"
_CPUCFLAGS = -march=pentium
.  else
_CPUCFLAGS = -march=${CPUTYPE}
.  endif # GCC on 'i386'
. elif ${MACHINE_ARCH} == "x86_64"
_CPUCFLAGS = -march=${CPUTYPE}
. endif

# Set up the list of CPU features based on the CPU type.  This is an
# unordered list to make it easy for client makefiles to test for the
# presence of a CPU feature.

. if ${MACHINE_ARCH} == "i386"
.  if ${CPUTYPE} == "opteron" || ${CPUTYPE} == "athlon64"
MACHINE_CPU = athlon-xp athlon k7 3dnow sse2 sse mmx k6 k5 i586 i486 i386
.  elif ${CPUTYPE} == "athlon-mp" || ${CPUTYPE} == "athlon-xp" || \
    ${CPUTYPE} == "athlon-4"
MACHINE_CPU = athlon-xp athlon k7 3dnow sse mmx k6 k5 i586 i486 i386
.  elif ${CPUTYPE} == "athlon" || ${CPUTYPE} == "athlon-tbird"
MACHINE_CPU = athlon k7 3dnow mmx k6 k5 i586 i486 i386
.  elif ${CPUTYPE} == "k6-3" || ${CPUTYPE} == "k6-2"
MACHINE_CPU = 3dnow mmx k6 k5 i586 i486 i386
.  elif ${CPUTYPE} == "k6"
MACHINE_CPU = mmx k6 k5 i586 i486 i386
.  elif ${CPUTYPE} == "k5"
MACHINE_CPU = k5 i586 i486 i386
.  elif ${CPUTYPE} == "c3"
MACHINE_CPU = 3dnow mmx i586 i486 i386
.  elif ${CPUTYPE} == "c3-2"
MACHINE_CPU = sse mmx i586 i486 i386
.  elif ${CPUTYPE} == "prescott"
MACHINE_CPU = sse3 sse2 sse i686 mmx i586 i486 i386
.  elif ${CPUTYPE} == "pentium4" || ${CPUTYPE} == "pentium4m" || ${CPUTYPE} == "pentium-m"
MACHINE_CPU = sse2 sse i686 mmx i586 i486 i386
.  elif ${CPUTYPE} == "pentium3" || ${CPUTYPE} == "pentium3m"
MACHINE_CPU = sse i686 mmx i586 i486 i386
.  elif ${CPUTYPE} == "pentium2"
MACHINE_CPU = i686 mmx i586 i486 i386
.  elif ${CPUTYPE} == "pentiumpro"
MACHINE_CPU = i686 i586 i486 i386
.  elif ${CPUTYPE} == "pentium-mmx"
MACHINE_CPU = mmx i586 i486 i386
.  elif ${CPUTYPE} == "pentium"
MACHINE_CPU = i586 i486 i386
.  elif ${CPUTYPE} == "i486"
MACHINE_CPU = i486 i386
.  elif ${CPUTYPE} == "i386"
MACHINE_CPU = i386
.  endif
. elif ${MACHINE_ARCH} == "x86_64"
.  if ${CPUTYPE} == "opteron" || ${CPUTYPE} == "athlon64" || ${CPUTYPE} == "k8"
MACHINE_CPU = k8 3dnow
.  elif ${CPUTYPE} == "nocona"
MACHINE_CPU = sse3
.  endif
MACHINE_CPU += x86_64 sse2 sse mmx
. endif
.endif
