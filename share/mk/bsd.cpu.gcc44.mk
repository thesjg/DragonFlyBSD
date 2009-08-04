# Set default CPU compile flags and baseline CPUTYPE for each arch.  The
# compile flags must support the minimum CPU type for each architecture but
# may tune support for more advanced processors.

.if !defined(CPUTYPE) || empty(CPUTYPE)
. if ${MACHINE_ARCH} == "i386"
CPUTYPE = i686
. elif ${MACHINE_ARCH} == "amd64"
CPUTYPE = athlon64
. endif
.endif

# Handle aliases (not documented in make.conf to avoid user confusion
# between e.g. i586 and pentium)

.if ${CPUTYPE} == "core"
CPUTYPE = nocona
.elif ${CPUTYPE} == "p4"
CPUTYPE = pentium4
.elif ${CPUTYPE} == "p4m"
CPUTYPE = pentium4m
.elif ${CPUTYPE} == "p3"
CPUTYPE = pentium3
.elif ${CPUTYPE} == "p3m"
CPUTYPE = pentium3m
.elif ${CPUTYPE} == "p-m"
CPUTYPE = pentium-m
.elif ${CPUTYPE} == "p2"
CPUTYPE = pentium2
.elif ${CPUTYPE} == "i586/mmx"
CPUTYPE = pentium-mmx
.elif ${CPUTYPE} == "i586"
CPUTYPE = pentium
.elif ${CPUTYPE} == "opteron" || ${CPUTYPE} == "k8"
CPUTYPE = athlon64
.elif ${CPUTYPE} == "k7"
CPUTYPE = athlon
.endif

###############################################################################
# Logic to set up correct gcc optimization flag.  This must be included
# after /etc/make.conf so it can react to the local value of CPUTYPE
# defined therein.  Consult:
#	http://gcc.gnu.org/onlinedocs/gcc/ARM-Options.html
#	http://gcc.gnu.org/onlinedocs/gcc/IA-64-Options.html
#	http://gcc.gnu.org/onlinedocs/gcc/RS-6000-and-PowerPC-Options.html
#	http://gcc.gnu.org/onlinedocs/gcc/SPARC-Options.html
#	http://gcc.gnu.org/onlinedocs/gcc/i386-and-x86-64-Options.html

.if ${MACHINE_ARCH} == "i386"
. if ${CPUTYPE} == "crusoe"
_CPUCFLAGS = -march=i686 -falign-functions=0 -falign-jumps=0 -falign-loops=0
. elif ${CPUTYPE} == "k5"
_CPUCFLAGS = -march=pentium
. else
_CPUCFLAGS = -march=${CPUTYPE}
. endif # GCC on 'i386'
.elif ${MACHINE_ARCH} == "amd64"
_CPUCFLAGS = -march=${CPUTYPE}
.endif

# Set up the list of CPU features based on the CPU type.  This is an
# unordered list to make it easy for client makefiles to test for the
# presence of a CPU feature.

.if ${MACHINE_ARCH} == "i386"
. if ${CPUTYPE} == "athlon64-sse"
MACHINE_CPU = athlon-xp athlon k7 3dnow sse3 sse2 sse mmx k6 k5 i586 i486 i386
. elif ${CPUTYPE} == "athlon64"
MACHINE_CPU = athlon-xp athlon k7 3dnow sse2 sse mmx k6 k5 i586 i486 i386
. elif ${CPUTYPE} == "athlon-mp" || ${CPUTYPE} == "athlon-xp" || ${CPUTYPE} == "athlon-4"
MACHINE_CPU = athlon-xp athlon k7 3dnow sse mmx k6 k5 i586 i486 i386
. elif ${CPUTYPE} == "athlon" || ${CPUTYPE} == "athlon-tbird"
MACHINE_CPU = athlon k7 3dnow mmx k6 k5 i586 i486 i386
. elif ${CPUTYPE} == "k6-3" || ${CPUTYPE} == "k6-2"
MACHINE_CPU = 3dnow mmx k6 k5 i586 i486 i386
. elif ${CPUTYPE} == "k6"
MACHINE_CPU = mmx k6 k5 i586 i486 i386
. elif ${CPUTYPE} == "k5"
MACHINE_CPU = k5 i586 i486 i386
. elif ${CPUTYPE} == "c3"
MACHINE_CPU = 3dnow mmx i586 i486 i386
. elif ${CPUTYPE} == "c3-2"
MACHINE_CPU = sse mmx i586 i486 i386
. elif ${CPUTYPE} == "core2"
MACHINE_CPU = ssse3 sse3 sse2 sse i686 mmx i586 i486 i386
. elif ${CPUTYPE} == "prescott" || ${CPUTYPE} == "nocona"
MACHINE_CPU = sse3 sse2 sse i686 mmx i586 i486 i386
. elif ${CPUTYPE} == "pentium4" || ${CPUTYPE} == "pentium4m" || ${CPUTYPE} == "pentium-m"
MACHINE_CPU = sse2 sse i686 mmx i586 i486 i386
. elif ${CPUTYPE} == "pentium3" || ${CPUTYPE} == "pentium3m"
MACHINE_CPU = sse i686 mmx i586 i486 i386
. elif ${CPUTYPE} == "pentium2"
MACHINE_CPU = i686 mmx i586 i486 i386
. elif ${CPUTYPE} == "pentiumpro"
MACHINE_CPU = i686 i586 i486 i386
. elif ${CPUTYPE} == "pentium-mmx"
MACHINE_CPU = mmx i586 i486 i386
. elif ${CPUTYPE} == "pentium"
MACHINE_CPU = i586 i486 i386
. elif ${CPUTYPE} == "i486"
MACHINE_CPU = i486 i386
. elif ${CPUTYPE} == "i386"
MACHINE_CPU = i386
. endif
.elif ${MACHINE_ARCH} == "amd64"
. if ${CPUTYPE} == "athlon64-sse3"
MACHINE_CPU = k8 3dnow sse3
. elif ${CPUTYPE} == "athlon64"
MACHINE_CPU = k8 3dnow
. elif ${CPUTYPE} == "nocona"
MACHINE_CPU = sse3
. elif ${CPUTYPE} == "core2"
MACHINE_CPU = ssse3 sse3
. endif
MACHINE_CPU += amd64 sse2 sse mmx
.endif