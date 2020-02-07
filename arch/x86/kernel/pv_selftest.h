/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PVR_SELFTEST_H
#define _PVR_SELFTEST_H

#ifdef CONFIG_DEBUG_PARAVIRT_SELFTEST
void pv_selftest_send_nmi(void);
void pv_selftest_primary(void);
void pv_selftest_secondary(void);
#else
static inline void pv_selftest_send_nmi(void) { }
static inline void pv_selftest_primary(void) { }
static inline void pv_selftest_secondary(void) { }
#endif /*! CONFIG_DEBUG_PARAVIRT_SELFTEST */

#endif /* _PVR_SELFTEST_H */
