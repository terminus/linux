/*
 * Xen Event Channels (internal header)
 *
 * Copyright (C) 2013 Citrix Systems R&D Ltd.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2 or later.  See the file COPYING for more details.
 */
#ifndef __EVENTS_INTERNAL_H__
#define __EVENTS_INTERNAL_H__

/* Interrupt types. */
enum xen_irq_type {
	IRQT_UNBOUND = 0,
	IRQT_PIRQ,
	IRQT_VIRQ,
	IRQT_IPI,
	IRQT_EVTCHN
};

/*
 * Packed IRQ information:
 * type - enum xen_irq_type
 * xh - xenhost_t *
 * event channel - irq->event channel mapping
 * cpu - cpu this event channel is bound to
 * index - type-specific information:
 *    PIRQ - vector, with MSB being "needs EIO", or physical IRQ of the HVM
 *           guest, or GSI (real passthrough IRQ) of the device.
 *    VIRQ - virq number
 *    IPI - IPI vector
 *    EVTCHN -
 */
struct irq_info {
	struct list_head list;
	xenhost_t *xh;
	int refcnt;
	enum xen_irq_type type;	/* type */
	unsigned irq;
	unsigned int evtchn;	/* event channel */
	unsigned short cpu;	/* cpu bound */

	union {
		unsigned short virq;
		enum ipi_vector ipi;
		struct {
			unsigned short pirq;
			unsigned short gsi;
			unsigned char vector;
			unsigned char flags;
			uint16_t domid;
		} pirq;
	} u;
};

#define PIRQ_NEEDS_EOI	(1 << 0)
#define PIRQ_SHAREABLE	(1 << 1)
#define PIRQ_MSI_GROUP	(1 << 2)

struct evtchn_ops {
	unsigned (*max_channels)(xenhost_t *xh);
	unsigned (*nr_channels)(xenhost_t *xh);

	int (*setup)(struct irq_info *info);
	void (*bind_to_cpu)(struct irq_info *info, unsigned cpu);

	void (*clear_pending)(xenhost_t *xh, unsigned port);
	void (*set_pending)(xenhost_t *xh, unsigned port);
	bool (*is_pending)(xenhost_t *xh, unsigned port);
	bool (*test_and_set_mask)(xenhost_t *xh, unsigned port);
	void (*mask)(xenhost_t *xh, unsigned port);
	void (*unmask)(xenhost_t *xh, unsigned port);

	void (*handle_events)(xenhost_t *xh, unsigned cpu);
	void (*resume)(xenhost_t *xh);
};

int get_evtchn_to_irq(xenhost_t *xh, unsigned int evtchn);

struct irq_info *info_for_irq(unsigned irq);
unsigned cpu_from_irq(unsigned irq);
unsigned cpu_from_evtchn(xenhost_t *xh, unsigned int evtchn);

static inline unsigned xen_evtchn_max_channels(xenhost_t *xh)
{
	return xh->evtchn_ops->max_channels(xh);
}

/*
 * Do any ABI specific setup for a bound event channel before it can
 * be unmasked and used.
 */
static inline int xen_evtchn_port_setup(struct irq_info *info)
{
	if (info->xh->evtchn_ops->setup)
		return info->xh->evtchn_ops->setup(info);
	return 0;
}

static inline void xen_evtchn_port_bind_to_cpu(struct irq_info *info,
					       unsigned cpu)
{
	info->xh->evtchn_ops->bind_to_cpu(info, cpu);
}

static inline void clear_evtchn(xenhost_t *xh, unsigned port)
{
	xh->evtchn_ops->clear_pending(xh, port);
}

static inline void set_evtchn(xenhost_t *xh, unsigned port)
{
	xh->evtchn_ops->set_pending(xh, port);
}

static inline bool test_evtchn(xenhost_t *xh, unsigned port)
{
	return xh->evtchn_ops->is_pending(xh, port);
}

static inline bool test_and_set_mask(xenhost_t *xh, unsigned port)
{
	return xh->evtchn_ops->test_and_set_mask(xh, port);
}

static inline void mask_evtchn(xenhost_t *xh, unsigned port)
{
	return xh->evtchn_ops->mask(xh, port);
}

static inline void unmask_evtchn(xenhost_t *xh, unsigned port)
{
	return xh->evtchn_ops->unmask(xh, port);
}

static inline void xen_evtchn_handle_events(xenhost_t *xh, unsigned cpu)
{
	return xh->evtchn_ops->handle_events(xh, cpu);
}

static inline void xen_evtchn_resume(void)
{
	xenhost_t **xh;

	for_each_xenhost(xh)
		if ((*xh)->evtchn_ops->resume)
			(*xh)->evtchn_ops->resume(*xh);
}

void xen_evtchn_2l_init(xenhost_t *xh);
int xen_evtchn_fifo_init(xenhost_t *xh);

#endif /* #ifndef __EVENTS_INTERNAL_H__ */
