.include "${.CURDIR}/../../platform/${MACHINE_PLATFORM}/Makefile.inc"

SUBDIR= aha ahci aic aic7xxx ccd dm iscsi ispfw md mmcsd mps mpt ncv nsp
SUBDIR+= sbp sdhci sili stg trm vn vpo

.for dir in ${SUBDIR}
.if empty(DEV_SUPPORT:Mdisk) && \
	empty(DEV_SUPPORT:Mdisk/${dir}) && empty(DEV_SUPPORT:Mdisk/${dir}/*)
SUBDIR:= ${SUBDIR:N${dir}}
.endif
.endfor

.include <bsd.subdir.mk>
