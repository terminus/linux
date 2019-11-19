// SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2018  Oracle and/or its affiliates. All rights reserved.
 *
 * Pv Reenlightenment Support
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/pvreenlight.h>

#define PVREENLIGHTEN_EVENT        (0)
#define ACPI_REENLIGHTEN_DEVICE_HID "QEMU0003"

MODULE_DESCRIPTION("PV reenlightenment device driver");
MODULE_LICENSE("GPL");

static int pvreenlighten_add(struct acpi_device *device);
static int pvreenlighten_remove(struct acpi_device *device);
static void pvreenlighten_notify(acpi_handle handle, u32 event, void *data);

static const struct acpi_device_id pvreenlighten_device_ids[] = {
	{ ACPI_REENLIGHTEN_DEVICE_HID, 0 },
	{ "", 0 }
};
MODULE_DEVICE_TABLE(acpi, pvreenlighten_device_ids);

static struct acpi_driver pvreenlighten_driver = {
	.name =		"pvreenlighten",
	.class =	"QEMU",
	.ids =		pvreenlighten_device_ids,
	.ops =		{
				.add =		pvreenlighten_add,
				.remove =	pvreenlighten_remove,
			},
	.owner =	THIS_MODULE,
};

static acpi_status is_pvreenlighten_device(acpi_handle handle)
{
	char *hardware_id;
	acpi_status status;
	struct acpi_device_info *info;

	status = acpi_get_object_info(handle, &info);
	if (ACPI_FAILURE(status))
		return status;

	if (!(info->valid & ACPI_VALID_HID)) {
		kfree(info);
		return AE_ERROR;
	}

	hardware_id = info->hardware_id.string;
	if ((hardware_id == NULL) ||
	    (strcmp(hardware_id, ACPI_REENLIGHTEN_DEVICE_HID)))
		status = AE_ERROR;

	kfree(info);
	return status;
}


static acpi_status
acpi_pvreenlighten_register_notify_handler(acpi_handle handle,
				    u32 level, void *ctxt, void **retv)
{
	acpi_status status;

	status = is_pvreenlighten_device(handle);
	if (ACPI_FAILURE(status))
		return AE_OK;	/* continue */

	status = acpi_install_notify_handler(handle, ACPI_SYSTEM_NOTIFY,
					     pvreenlighten_notify, NULL);
	/* continue */
	return AE_OK;
}

static int pvreenlighten_add(struct acpi_device *device)
{
	acpi_status status;
	int ret;

	ret = acpi_bus_get_status(device);
	if (ret < 0) {
		pr_err("Failed to get status\n");
		return ret;
	}

	if (!device->status.enabled || !device->status.functional) {
		pr_err("Device not enabled or functional\n");
		return -ENODEV;
	}

	status = acpi_walk_namespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT,
				     ACPI_UINT32_MAX,
				     acpi_pvreenlighten_register_notify_handler,
				     NULL, NULL, NULL);
	if (ACPI_FAILURE(status)) {
		pr_warn("Failed to register notify handler\n");
		acpi_bus_unregister_driver(&pvreenlighten_driver);
		return -ENODEV;
	}

	pr_info("PV reenlightenment device loaded\n");
	return 0;
}

static int pvreenlighten_remove(struct acpi_device *device)
{
	return 0;
}

static void pvreenlighten_notify(acpi_handle handle, u32 event, void *data)
{
	unsigned int cpu = smp_processor_id();

	arch_reenlighten_notify(cpu);
}

static int pvreenlighten_register_acpi_driver(void)
{
	return acpi_bus_register_driver(&pvreenlighten_driver);
}

static void pvreenlighten_unregister_acpi_driver(void)
{
	acpi_bus_unregister_driver(&pvreenlighten_driver);
}

static int __init pvreenlighten_init(void)
{
	int ret;

	if (acpi_disabled)
		return -ENODEV;

	ret = pvreenlighten_register_acpi_driver();
	if (ret < 0) {
		pr_err("Failed to register ACPI driver err %d\n", ret);
		return -ENODEV;
	}

	return ret;
}

static void __exit pvreenlighten_exit(void)
{
	pvreenlighten_unregister_acpi_driver();
}

module_init(pvreenlighten_init);
module_exit(pvreenlighten_exit);
