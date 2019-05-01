/* SPDX-License-Identifier: GPL-2.0 */
/******************************************************************************
 * features.h
 *
 * Query the features reported by Xen.
 *
 * Copyright (c) 2006, Ian Campbell
 */

#ifndef __XEN_FEATURES_H__
#define __XEN_FEATURES_H__

#include <xen/interface/features.h>
#include <xen/xenhost.h>

void xen_setup_features(xenhost_t *xh);

bool xen_validate_features(void);

static inline int __xen_feature(xenhost_t *xh, int flag)
{
	return xh->features[flag];
}

/*
 * We've validated the features that need to be common for both xenhost_r1 and
 * xenhost_r2 (XENFEAT_hvm_callback_vector, XENFEAT_auto_translated_physmap.)
 * Most of the other features should be only needed for the default xenhost.
 */
static inline int xen_feature(int flag)
{
	return __xen_feature(xh_default, flag);
}

#endif /* __ASM_XEN_FEATURES_H__ */
