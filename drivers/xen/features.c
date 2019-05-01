/******************************************************************************
 * features.c
 *
 * Xen feature flags.
 *
 * Copyright (c) 2006, Ian Campbell, XenSource Inc.
 */
#include <linux/types.h>
#include <linux/cache.h>
#include <linux/export.h>

#include <asm/xen/hypercall.h>

#include <xen/interface/xen.h>
#include <xen/interface/version.h>
#include <xen/features.h>

void xen_setup_features(xenhost_t *xh)
{
	struct xen_feature_info fi;
	int i, j;

	for (i = 0; i < XENFEAT_NR_SUBMAPS; i++) {
		fi.submap_idx = i;
		if (hypervisor_xen_version(xh, XENVER_get_features, &fi) < 0)
			break;
		for (j = 0; j < 32; j++)
			xh->features[i * 32 + j] = !!(fi.submap & 1<<j);
	}
}

bool xen_validate_features(void)
{
	int fail = 0;

	if (xh_default && xh_remote) {
		/*
		 * Check xh_default->features and xh_remote->features for
		 * compatibility. Relevant features should be compatible
		 * or we are asking for trouble.
		 */
		fail += __xen_feature(xh_default, XENFEAT_auto_translated_physmap) !=
			__xen_feature(xh_remote, XENFEAT_auto_translated_physmap);

		/* We would like callbacks via hvm_callback_vector. */
		fail += __xen_feature(xh_default, XENFEAT_hvm_callback_vector) == 0;
		fail += __xen_feature(xh_remote, XENFEAT_hvm_callback_vector) == 0;

		if (fail)
			return false;
	}

	return fail ? false : true;
}
