/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PVREENLIGHTEN_H
#define _PVREENLIGHTEN_H

#ifdef CONFIG_ARCH_PVREENLIGHT
#include <asm/pvreenlight.h>
#else
static inline void arch_reenlighten_notify(unsigned int cpu) { }
#endif
#endif /* _PVREENLIGHTEN_H */
