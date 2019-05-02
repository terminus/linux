#include <linux/types.h>
#include <linux/bug.h>
#include <xen/xen.h>
#include <xen/xenhost.h>
#include "xen-ops.h"

/*
 * Point at some empty memory to start with. On PV, we map the real shared_info
 * page as soon as fixmap is up and running and PVH* doesn't use this.
 */
xenhost_t xenhosts[2] = {
	/*
	 * We should probably have two separate dummy shared_info pages.
	 */
	[0].HYPERVISOR_shared_info = &xen_dummy_shared_info,
	[1].HYPERVISOR_shared_info = &xen_dummy_shared_info,
};
/*
 * xh_default: interface to the regular hypervisor. xenhost_type is xenhost_r0
 * or xenhost_r1.
 *
 * xh_remote: interface to remote hypervisor. Needed for PV driver support on
 * L1-dom0/driver-domain for nested Xen. xenhost_type is xenhost_r2.
 */
xenhost_t *xh_default = (xenhost_t *) &xenhosts[0];
xenhost_t *xh_remote = (xenhost_t *) &xenhosts[1];

/*
 * Exported for use of for_each_xenhost().
 */
EXPORT_SYMBOL_GPL(xenhosts);

/*
 * Some places refer directly to a specific type of xenhost.
 * This might be better as a macro though.
 */
EXPORT_SYMBOL_GPL(xh_default);
EXPORT_SYMBOL_GPL(xh_remote);

void xenhost_register(enum xenhost_type type, xenhost_ops_t *ops)
{
	switch (type) {
		case xenhost_r0:
		case xenhost_r1:
			BUG_ON(xh_default->type != xenhost_invalid);

			xh_default->type = type;
			xh_default->ops = ops;
			break;
		case xenhost_r2:
			BUG_ON(xh_remote->type != xenhost_invalid);

			/*
			 * We should have a default xenhost by the
			 * time xh_remote is registered.
			 */
			BUG_ON(!xh_default);

			xh_remote->type = type;
			xh_remote->ops = ops;
			break;
		default:
			BUG();
	}
}

/*
 * __xenhost_unregister: expected to be called only if there's an
 * error early in the init.
 */
void __xenhost_unregister(enum xenhost_type type)
{
	switch (type) {
		case xenhost_r0:
		case xenhost_r1:
			xh_default->type = xenhost_invalid;
			xh_default->ops = NULL;
			break;
		case xenhost_r2:
			xh_remote->type = xenhost_invalid;
			xh_remote->ops = NULL;
			break;
		default:
			BUG();
	}
}
