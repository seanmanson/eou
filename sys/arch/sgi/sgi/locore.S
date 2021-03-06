/*	$OpenBSD: locore.S,v 1.15 2012/10/03 11:18:23 miod Exp $ */

/*
 * Copyright (c) 2001-2004 Opsycon AB  (www.opsycon.se / www.opsycon.com)
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include <sys/errno.h>
#include <sys/syscall.h>

#include <machine/param.h>
#include <machine/asm.h>
#include <machine/cpu.h>
#include <mips64/mips_cpu.h>
#include <machine/regnum.h>
#include <machine/cpustate.h>

#include "assym.h"

	.set	mips3
	.set	noreorder		# Noreorder is default style!

	.globl	start
	.globl	kernel_text
kernel_text = start
start:
	/*
	 * On at least the O2, when netbooting the bsd.rd kernel, the
	 * kernel image gets loaded in CKSEG1, which causes the kernel
	 * text to be uncached.  Just to be on the safe side, jump to
	 * our intended execution address.
	 */
	LA	v0, 1f
	jr	v0
	 NOP
1:

	MFC0	v0, COP_0_STATUS_REG
	LI	v1, ~SR_INT_ENAB
	and	v0, v1
	MTC0	v0, COP_0_STATUS_REG		# disable all interrupts
	MTC0_SR_IE_HAZARD
	MTC0	zero, COP_0_CAUSE_REG		# Clear soft interrupts
	MTC0_HAZARD

	/*
	 * Initialize stack and call machine startup.
	 */
	LA	sp, start - FRAMESZ(CF_SZ)
	LA	gp, _gp
	jal	mips_init			# mips_init(argc, argv, envp)
	PTR_S	zero, CF_RA_OFFS(sp)		# Zero out old ra for debugger

	move	sp, v0				# switch to new stack
	jal	main				# main(regs)
	 move	a0, zero
	PANIC("Startup failed!")

#if defined(MULTIPROCESSOR)
LEAF(hw_cpu_spinup_trampoline, 0)
	MFC0	v0, COP_0_STATUS_REG
	LI	v1, ~SR_INT_ENAB
	and	v0, v1
	ori	v0, SR_KX | SR_UX
	MTC0	v0, COP_0_STATUS_REG		# disable all interrupts
	MTC0	zero, COP_0_CAUSE_REG		# Clear soft interrupts
	LA	gp, _gp
	jal	hw_cpu_hatch
	 NOP
END(hw_cpu_spinup_trampoline)

#ifdef TGT_OCTANE

LEAF(hw_getcurcpu, 0)
	GET_CPU_INFO(v0, v1)
	j	ra
	 NOP
END(hw_getcurcpu)

/*
 * There does not seem to be any fast way to store the curcpu pointer on
 * Octane. We used to abuse the LLAddr register, but this is a 32-bit register,
 * not suitable for allocation over 2GB physical.
 * Instead, we will use an unused field of the MPCONF structure.
 */
LEAF(hw_setcurcpu, 0)
	HW_GET_CPU_PRID(v0, v1)			# get physical processor ID
	LOAD_XKPHYS(v1, CCA_COHERENT_EXCLWRITE)
	PTR_SLL	v0, MPCONF_SHIFT
	PTR_ADD	v0, MPCONF_BASE
	or	v1, v0
	j	ra
	 PTR_S	a0, (MPCONF_LEN - REGSZ)(v1)
END(hw_setcurcpu)
#endif
#endif /* MULTIPROCESSOR */
