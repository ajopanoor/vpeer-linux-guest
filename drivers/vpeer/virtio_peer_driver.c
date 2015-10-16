/*
 * Virtio-Peer Driver
 *
 * Copyright (C) 2015 Huawei Technologies GmbH
 *
 * Ajo Jose Panoor <ajo.jose.panoor@huawei.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include "virtio_peer.h"

/**
 * struct virtpeer_info - virtio peer state
 * @vdev:	the virtio device
 * @rvq:	rx virtqueue
 * @svq:	tx virtqueue
 * @rbufs:	kernel address of rx buffers
 * @sbufs:	kernel address of tx buffers
 * @num_bufs:	total number of buffers for rx and tx
 * @last_sbuf:	index of last tx buffer used
 * @bufs_dma:	dma base addr of the buffers
 * @tx_lock:	protects svq & sbufs  to allow concurrent senders.
 */
struct vpeer_info {
	struct virtio_device *vdev;
	struct virtqueue *rvq, *svq;
	void *rbufs, *sbufs;
	unsigned int num_bufs;
	int last_sbuf;
	dma_addr_t bufs_dma;
	struct mutex tx_lock;
	struct virtio_peer_config cfg;
};

struct vpeer_info *g_vp;

#define MAX_VPEER_NUM_BUFS	(512)
#define VPEER_BUF_SIZE		(512)

/* super simple buffer "allocator" that is just enough for now */
static void *get_a_tx_buf(struct vpeer_info *vp)
{
	unsigned int len;
	void *ret;

	/* support multiple concurrent senders */
	mutex_lock(&vp->tx_lock);

	/*
	 * either pick the next unused tx buffer
	 * (half of our buffers are used for sending messages)
	 */
	if (vp->last_sbuf < vp->num_bufs / 2)
		ret = vp->sbufs + VPEER_BUF_SIZE * vp->last_sbuf++;
	/* or recycle a used one */
	else
		ret = virtqueue_get_buf(vp->svq, &len);

	mutex_unlock(&vp->tx_lock);

	return ret;
}

int vpeer_send(void *data, int len)
{
	struct vpeer_info *vp = g_vp;
	struct device *dev = &vp->vdev->dev;
	struct scatterlist sg;
	void *buf;
	int err;

	/* grab a buffer */
	buf = get_a_tx_buf(vp);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, data, len);

	print_hex_dump(KERN_DEBUG, "VPEER TX: ", DUMP_PREFIX_NONE, 16, 1,
					buf, len, true);

	sg_init_one(&sg, buf, len);

	mutex_lock(&vp->tx_lock);

	err = virtqueue_add_outbuf(vp->svq, &sg, 1, buf, GFP_KERNEL);
	if (err) {
		dev_err(dev, "virtqueue_add_outbuf failed: %d\n", err);
		goto out;
	}

	virtqueue_kick(vp->svq);
out:
	mutex_unlock(&vp->tx_lock);
	return err;
}

static int vpeer_recv_single(struct vpeer_info *vp, struct device *dev,
			     void *buf, unsigned int len)
{
	struct scatterlist sg;
	int err;

	print_hex_dump(KERN_DEBUG, "VPEER RX: ", DUMP_PREFIX_NONE, 16, 1,
					buf, len, true);

	sg_init_one(&sg, buf, VPEER_BUF_SIZE);

	err = virtqueue_add_inbuf(vp->rvq, &sg, 1, buf, GFP_KERNEL);
	if (err < 0) {
		dev_err(dev, "failed to add a virtqueue buffer: %d\n", err);
		return err;
	}

	return 0;
}

/* called when an rx buffer is used, and it's time to digest a message */
static void vpeer_recv_done(struct virtqueue *rvq)
{
	struct vpeer_info *vp = rvq->vdev->priv;
	struct device *dev = &rvq->vdev->dev;
	unsigned int len, bufs_received = 0;
	void *buf;
	int err;

	buf = virtqueue_get_buf(rvq, &len);
	if (!buf) {
		dev_err(dev, "no used buffer ?\n");
		return;
	}

	while (buf) {
		err = vpeer_recv_single(vp, dev, buf, len);
		if (err)
			break;

		bufs_received++;

		buf = virtqueue_get_buf(rvq, &len);
	};

	dev_info(dev, "Received %u messages\n", bufs_received);

	if (bufs_received)
		virtqueue_kick(vp->rvq);
}

static void vpeer_xmit_done(struct virtqueue *svq)
{
	dev_info(&svq->vdev->dev, "%s\n", __func__);
}

static int vpeer_probe(struct virtio_device *vdev)
{
	vq_callback_t *vq_cbs[] = { vpeer_recv_done, vpeer_xmit_done };
	const char *names[] = { "tx", "rx" };
	struct virtqueue *vqs[2];
	size_t total_buf_space;
	struct vpeer_info *vp;
	void *bufs_va;
	int err = 0, i;
	bool notify;

	vp = kzalloc(sizeof(*vp), GFP_KERNEL);
	if (!vp)
		return -ENOMEM;

	vp->vdev = vdev;

	mutex_init(&vp->tx_lock);

	/* We expect two virtqueues, rx and tx (and in this order) */
	err = vdev->config->find_vqs(vdev, 2, vqs, vq_cbs, names);
	if (err)
		goto free_vp;

	vp->rvq = vqs[0];
	vp->svq = vqs[1];

	/* we expect symmetric tx/rx vrings */
	WARN_ON(virtqueue_get_vring_size(vp->rvq) !=
		virtqueue_get_vring_size(vp->svq));

	/* we need less buffers if vrings are small */
	if (virtqueue_get_vring_size(vp->rvq) < MAX_VPEER_NUM_BUFS / 2)
		vp->num_bufs = virtqueue_get_vring_size(vp->rvq) * 2;
	else
		vp->num_bufs = MAX_VPEER_NUM_BUFS;

	total_buf_space = vp->num_bufs * VPEER_BUF_SIZE;

	/* allocate coherent memory for the buffers */
	bufs_va = dma_alloc_coherent(vdev->dev.parent,
				     total_buf_space, &vp->bufs_dma,
				     GFP_KERNEL);
	if (!bufs_va) {
		err = -ENOMEM;
		goto vqs_del;
	}

	vdev->config->get(vdev,
			offsetof(struct virtio_peer_config, queue_magic),
			&vp->cfg.queue_magic, sizeof(unsigned int));

	dev_info(&vdev->dev, "num_bufs %u bufs va %p, dma 0x%llx magic 0x%x\n",
					vp->num_bufs, bufs_va,
					(unsigned long long)vp->bufs_dma,
					vp->cfg.queue_magic);

	/* half of the buffers is dedicated for RX */
	vp->rbufs = bufs_va;

	/* and half is dedicated for TX */
	vp->sbufs = bufs_va + total_buf_space / 2;

	/* set up the receive buffers */
	for (i = 0; i < vp->num_bufs / 2; i++) {
		struct scatterlist sg;
		void *cpu_addr = vp->rbufs + i * VPEER_BUF_SIZE;

		sg_init_one(&sg, cpu_addr, VPEER_BUF_SIZE);

		err = virtqueue_add_inbuf(vp->rvq, &sg, 1, cpu_addr,
								GFP_KERNEL);
		WARN_ON(err); /* sanity check; this can't really happen */
	}

	virtqueue_disable_cb(vp->svq);

	g_vp = vdev->priv = vp; /* FIXME */

	notify = virtqueue_kick_prepare(vp->rvq);

	virtio_device_ready(vdev);

	if (notify)
		virtqueue_notify(vp->rvq);

	dev_info(&vdev->dev, "vpeer-lguest is online\n");

	return 0;

vqs_del:
	vdev->config->del_vqs(vp->vdev);
free_vp:
	kfree(vp);
	return err;
}

static int vpeer_remove_device(struct device *dev, void *data)
{
	device_unregister(dev);

	return 0;
}

static void vpeer_remove(struct virtio_device *vdev)
{
	struct vpeer_info *vp = vdev->priv;
	size_t total_buf_space = vp->num_bufs * VPEER_BUF_SIZE;
	int ret;

	vdev->config->reset(vdev);

	ret = device_for_each_child(&vdev->dev, NULL, vpeer_remove_device);
	if (ret)
		dev_warn(&vdev->dev, "can't remove vpeer device: %d\n", ret);

	vdev->config->del_vqs(vp->vdev);

	dma_free_coherent(vdev->dev.parent, total_buf_space,
			  vp->rbufs, vp->bufs_dma);

	kfree(vp);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_PEER, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	0,
};

static struct virtio_driver virtio_peer_driver = {
	.feature_table	= features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name	= KBUILD_MODNAME,
	.driver.owner	= THIS_MODULE,
	.id_table	= id_table,
	.probe		= vpeer_probe,
	.remove		= vpeer_remove,
};

static int __init vpeer_init(void)
{
	int ret;

	ret = register_virtio_driver(&virtio_peer_driver);
	if (ret)
		pr_err("failed to register virtio driver: %d\n", ret);

	return ret;
}
subsys_initcall(vpeer_init);

static void __exit vpeer_fini(void)
{
	unregister_virtio_driver(&virtio_peer_driver);
}
module_exit(vpeer_fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio-peer Driver");
MODULE_LICENSE("GPL v2");
