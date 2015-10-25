/*
 * Virtio PCI Window driver - modern (virtio 1.0) peer device support
 *
 * This module allows virtio peer  devices to be used over a virtual PCI device.
 * This can be used with QEMU based VMMs like KVM or Xen.
 *
 * Copyright Huawei Technologies 2015
 *
 * Authors:
 *  	Ajo Jose Panoor<ajo.jose.panoor@huawei.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#define VIRTIO_PCI_NO_LEGACY
#include "virtio_pci_common.h"
#define LOCAL_VQ	0
#define REMOTE_VQ	1

#define WINDOW_ALIGN(addr, align)	(((addr) + (align -1)) & ~(align -1))

static void *window_alloc_virtqueue_vrings(struct virtio_pci_device *vp_dev,
		struct vring *vr, int num, int qtype)
{
	struct virtio_window *vp_win = &vp_dev->window;
	size_t desc_size, avail_size, used_size;
	void *rva, *wva;

	if (qtype == LOCAL_VQ) {
		wva = vp_win->wva;
		rva = vp_win->rva;
	} else {
		rva = vp_win->wva;
		wva = vp_win->rva;
	}
	desc_size = PAGE_ALIGN(WINDOW_ALIGN((sizeof(struct vring_desc) * (num)),
			SMP_CACHE_BYTES));

	avail_size = PAGE_ALIGN(WINDOW_ALIGN((sizeof(__virtio16) * (3 + num)),
			SMP_CACHE_BYTES));

	used_size = PAGE_ALIGN(WINDOW_ALIGN((sizeof(__virtio16) * 3 +
			sizeof(struct vring_used_elem) * num),
			SMP_CACHE_BYTES));
	vr->num = num;
	vr->desc = wva;
	vr->avail = wva + desc_size;
	vr->used = rva + desc_size + avail_size;
	return wva;
}

struct virtqueue *setup_vq_window(struct virtio_pci_device *vp_dev,
				  struct virtio_pci_vq_info *info,
				  unsigned index,
				  void (*callback)(struct virtqueue *vq),
				  const char *name,
				  u16 msix_vec)
{
	struct virtio_pci_window_cfg __iomem *wcfg = vp_dev->window.wcfg;
	struct virtio_pci_common_cfg __iomem *cfg = vp_dev->common;
	struct virtio_window *vp_win = &vp_dev->window;
	struct virtqueue *vq;
	struct vring vr;
	u16 num, off;
	int err;

	if (index >= ioread16(&cfg->num_queues))
		return ERR_PTR(-ENOENT);

	if (!vp_win->enable)
		return ERR_PTR(-EINVAL);

	/* Select the queue we're interested in */
	iowrite16(index, &cfg->queue_select);

	/* Check if queue is either not available or already active. */
	num = ioread16(&cfg->queue_size);
	if (!num || ioread16(&cfg->queue_enable))
		return ERR_PTR(-ENOENT);

	if (num & (num - 1)) {
		dev_warn(&vp_dev->pci_dev->dev, "bad queue size %u", num);
		return ERR_PTR(-EINVAL);
	}

	/* get offset of notification word for this vq */
	off = ioread16(&cfg->queue_notify_off);

	info->num = num;
	info->msix_vector = msix_vec;

	info->queue = window_alloc_virtqueue_vrings(vp_dev, &vr, num, LOCAL_VQ);
	if (info->queue == NULL)
		return ERR_PTR(-ENOMEM);

	/* create the vring */
	vq = vring_new_virtqueue(index, info->num,
				 SMP_CACHE_BYTES, &vp_dev->vdev,
				 true, info->queue, vp_notify, callback, name);
	if (!vq) {
		err = -ENOMEM;
		goto err_new_queue;
	}

	/* activate the queue */
	iowrite16(num, &cfg->queue_size);
	vp_iowrite64_twopart(virt_to_phys(info->queue),
			     &cfg->queue_desc_lo, &cfg->queue_desc_hi);
	vp_iowrite64_twopart(virt_to_phys(virtqueue_get_avail(vq)),
			     &cfg->queue_avail_lo, &cfg->queue_avail_hi);
	vp_iowrite64_twopart(virt_to_phys(virtqueue_get_used(vq)),
			     &cfg->queue_used_lo, &cfg->queue_used_hi);

	if (vp_dev->notify_base) {
		/* offset should not wrap */
		if ((u64)off * vp_dev->notify_offset_multiplier + 2
		    > vp_dev->notify_len) {
			dev_warn(&vp_dev->pci_dev->dev,
				 "bad notification offset %u (x %u) "
				 "for queue %u > %zd",
				 off, vp_dev->notify_offset_multiplier,
				 index, vp_dev->notify_len);
			err = -EINVAL;
			goto err_map_notify;
		}
		vq->priv = (void __force *)vp_dev->notify_base +
			off * vp_dev->notify_offset_multiplier;
	} else {
		vq->priv = (void __force *)map_capability(vp_dev->pci_dev,
					  vp_dev->notify_map_cap, 2, 2,
					  off * vp_dev->notify_offset_multiplier, 2,
					  NULL);
	}

	if (!vq->priv) {
		err = -ENOMEM;
		goto err_map_notify;
	}

	if (msix_vec != VIRTIO_MSI_NO_VECTOR) {
		iowrite16(msix_vec, &cfg->queue_msix_vector);
		msix_vec = ioread16(&cfg->queue_msix_vector);
		if (msix_vec == VIRTIO_MSI_NO_VECTOR) {
			err = -EBUSY;
			goto err_assign_vector;
		}
	}

	return vq;

err_assign_vector:
	if (!vp_dev->notify_base)
		pci_iounmap(vp_dev->pci_dev, (void __iomem __force *)vq->priv);
err_map_notify:
	vring_del_virtqueue(vq);
err_new_queue:
	return ERR_PTR(err);
}

void del_vq_window(struct virtio_pci_vq_info *info)
{
	struct virtqueue *vq = info->vq;
	struct virtio_pci_device *vp_dev = to_vp_device(vq->vdev);

	iowrite16(vq->index, &vp_dev->common->queue_select);

	if (vp_dev->msix_enabled) {
		iowrite16(VIRTIO_MSI_NO_VECTOR,
			     &vp_dev->common->queue_msix_vector);
		/* Flush the write out to device */
		ioread16(&vp_dev->common->queue_msix_vector);
	}

	if (!vp_dev->notify_base)
		pci_iounmap(vp_dev->pci_dev, (void __force __iomem *)vq->priv);

	vring_del_virtqueue(vq);
}

void init_window(struct virtio_pci_device *vp_dev)
{
	struct virtio_window *vp_win = &vp_dev->window;
	struct virtio_window_config __iomem *wcfg = vp_win->wcfg;
	struct pci_dev *pci_dev = vp_dev->pci_dev;

	vp_win->rva = pci_ioremap_bar(pci_dev, ioread8(&wcfg->ro_bar));
	if(!vp_win->rva)
		return;

	vp_win->wva = pci_ioremap_bar(pci_dev, ioread8(&wcfg->rw_bar));
	if(!vp_win->rva)
		goto unmap_rva;

	vp_win->enable = true;

	dev_info(&pci_dev->dev, "WINDOW CFG: BARS (ro = %d, rw =%d) "
			"SIZE (ro = %d, rw = %d) VA (ro = %p rw= %p)\n",
			ioread8(&wcfg->ro_bar),ioread8(&wcfg->rw_bar),
			ioread32(&wcfg->ro_win_size),
			ioread32(&wcfg->rw_win_size),
			vp_win->rva, vp_win->wva);
	return;

unmap_rva:
	iounmap(vp_win->rva);
}
