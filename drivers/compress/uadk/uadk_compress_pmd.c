/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022-2023 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2022-2023 Linaro ltd.
 */

#include <rte_bus_pci.h>
#include <rte_compressdev_pmd.h>
#include <rte_malloc.h>
#include <uadk/wd_comp.h>
#include <uadk/wd_sched.h>

struct uadk_compress_priv {
	struct rte_mempool *mp;
} __rte_cache_aligned;

struct uadk_qp {
	struct rte_ring *processed_pkts;
	/**< Ring for placing process packets */
	struct rte_compressdev_stats qp_stats;
	/**< Queue pair statistics */
	uint16_t id;
	/**< Queue Pair Identifier */
	char name[RTE_COMPRESSDEV_NAME_MAX_LEN];
	/**< Unique Queue Pair Name */
} __rte_cache_aligned;

struct uadk_stream {
	handle_t handle;
	enum rte_comp_xform_type type;
} __rte_cache_aligned;

RTE_LOG_REGISTER_DEFAULT(uadk_compress_logtype, INFO);

#define UADK_LOG(level, fmt, ...)  \
	rte_log(RTE_LOG_ ## level, uadk_compress_logtype,  \
			"%s() line %u: " fmt "\n", __func__, __LINE__,  \
					## __VA_ARGS__)

#define UADK_COMPRESS_DRIVER_NAME compress_uadk

static int
uadk_compress_pmd_config(struct rte_compressdev *dev,
			 struct rte_compressdev_config *config)
{
	char mp_name[RTE_MEMPOOL_NAMESIZE];
	struct uadk_compress_priv *priv;
	struct rte_mempool *mp;
	int ret;

	if (dev == NULL || config == NULL)
		return -EINVAL;

	snprintf(mp_name, RTE_MEMPOOL_NAMESIZE,
		 "stream_mp_%u", dev->data->dev_id);
	priv = dev->data->dev_private;

	/* alloc resources */
	ret = wd_comp_env_init(NULL);
	if (ret < 0)
		return -EINVAL;

	mp = priv->mp;
	if (mp == NULL) {
		mp = rte_mempool_create(mp_name,
				config->max_nb_priv_xforms +
				config->max_nb_streams,
				sizeof(struct uadk_stream),
				0, 0, NULL, NULL, NULL,
				NULL, config->socket_id,
				0);
		if (mp == NULL) {
			UADK_LOG(ERR, "Cannot create private xform pool on socket %d\n",
				 config->socket_id);
			ret = -ENOMEM;
			goto err_mempool;
		}
		priv->mp = mp;
	}
	return 0;
err_mempool:
	wd_comp_env_uninit();
	return ret;
}

static int
uadk_compress_pmd_start(struct rte_compressdev *dev __rte_unused)
{
	return 0;
}

static void
uadk_compress_pmd_stop(struct rte_compressdev *dev __rte_unused)
{
}

static int
uadk_compress_pmd_close(struct rte_compressdev *dev)
{
	struct uadk_compress_priv *priv =
		(struct uadk_compress_priv *)dev->data->dev_private;

	/* free resources */
	rte_mempool_free(priv->mp);
	priv->mp = NULL;
	wd_comp_env_uninit();

	return 0;
}

static void
uadk_compress_pmd_stats_get(struct rte_compressdev *dev,
			    struct rte_compressdev_stats *stats)
{
	int qp_id;

	for (qp_id = 0; qp_id < dev->data->nb_queue_pairs; qp_id++) {
		struct uadk_qp *qp = dev->data->queue_pairs[qp_id];

		stats->enqueued_count += qp->qp_stats.enqueued_count;
		stats->dequeued_count += qp->qp_stats.dequeued_count;
		stats->enqueue_err_count += qp->qp_stats.enqueue_err_count;
		stats->dequeue_err_count += qp->qp_stats.dequeue_err_count;
	}
}

static void
uadk_compress_pmd_stats_reset(struct rte_compressdev *dev __rte_unused)
{
}

static const struct
rte_compressdev_capabilities uadk_compress_pmd_capabilities[] = {
	{   /* Deflate */
		.algo = RTE_COMP_ALGO_DEFLATE,
		.comp_feature_flags = RTE_COMP_FF_SHAREABLE_PRIV_XFORM |
				      RTE_COMP_FF_HUFFMAN_FIXED |
				      RTE_COMP_FF_HUFFMAN_DYNAMIC,
	},

	RTE_COMP_END_OF_CAPABILITIES_LIST()
};

static void
uadk_compress_pmd_info_get(struct rte_compressdev *dev,
			   struct rte_compressdev_info *dev_info)
{
	if (dev_info != NULL) {
		dev_info->driver_name = dev->device->driver->name;
		dev_info->feature_flags = dev->feature_flags;
		dev_info->capabilities = uadk_compress_pmd_capabilities;
	}
}

static int
uadk_compress_pmd_qp_release(struct rte_compressdev *dev, uint16_t qp_id)
{
	struct uadk_qp *qp = dev->data->queue_pairs[qp_id];

	if (qp != NULL) {
		rte_ring_free(qp->processed_pkts);
		rte_free(qp);
		dev->data->queue_pairs[qp_id] = NULL;
	}

	return 0;
}

static int
uadk_pmd_qp_set_unique_name(struct rte_compressdev *dev,
			    struct uadk_qp *qp)
{
	unsigned int n = snprintf(qp->name, sizeof(qp->name),
				 "uadk_pmd_%u_qp_%u",
				 dev->data->dev_id, qp->id);

	if (n >= sizeof(qp->name))
		return -1;

	return 0;
}

static struct rte_ring *
uadk_pmd_qp_create_processed_pkts_ring(struct uadk_qp *qp,
				       unsigned int ring_size, int socket_id)
{
	struct rte_ring *r = qp->processed_pkts;

	if (r) {
		if (rte_ring_get_size(r) >= ring_size) {
			UADK_LOG(INFO, "Reusing existing ring %s for processed packets",
				 qp->name);
			return r;
		}

		UADK_LOG(ERR, "Unable to reuse existing ring %s for processed packets",
			 qp->name);
		return NULL;
	}

	return rte_ring_create(qp->name, ring_size, socket_id,
			       RING_F_EXACT_SZ);
}

static int
uadk_compress_pmd_qp_setup(struct rte_compressdev *dev, uint16_t qp_id,
			   uint32_t max_inflight_ops, int socket_id)
{
	struct uadk_qp *qp = NULL;

	/* Free memory prior to re-allocation if needed. */
	if (dev->data->queue_pairs[qp_id] != NULL)
		uadk_compress_pmd_qp_release(dev, qp_id);

	/* Allocate the queue pair data structure. */
	qp = rte_zmalloc_socket("uadk PMD Queue Pair", sizeof(*qp),
				RTE_CACHE_LINE_SIZE, socket_id);
	if (qp == NULL)
		return (-ENOMEM);

	qp->id = qp_id;
	dev->data->queue_pairs[qp_id] = qp;

	if (uadk_pmd_qp_set_unique_name(dev, qp))
		goto qp_setup_cleanup;

	qp->processed_pkts = uadk_pmd_qp_create_processed_pkts_ring(qp,
						max_inflight_ops, socket_id);
	if (qp->processed_pkts == NULL)
		goto qp_setup_cleanup;

	memset(&qp->qp_stats, 0, sizeof(qp->qp_stats));
	return 0;

qp_setup_cleanup:
	if (qp) {
		rte_free(qp);
		qp = NULL;
	}
	return -1;
}

static int
uadk_compress_pmd_xform_create(struct rte_compressdev *dev,
			       const struct rte_comp_xform *xform,
			       void **private_xform)
{
	struct uadk_compress_priv *priv = dev->data->dev_private;
	struct wd_comp_sess_setup setup = {0};
	struct sched_params param = {0};
	struct uadk_stream *stream;
	handle_t handle;

	if (xform == NULL) {
		UADK_LOG(ERR, "invalid xform struct");
		return -EINVAL;
	}

	if (rte_mempool_get(priv->mp, private_xform)) {
		UADK_LOG(ERR, "Couldn't get object from session mempool");
		return -ENOMEM;
	}

	stream = *((struct uadk_stream **)private_xform);

	switch (xform->type) {
	case RTE_COMP_COMPRESS:
		switch (xform->compress.algo) {
		case RTE_COMP_ALGO_NULL:
			break;
		case RTE_COMP_ALGO_DEFLATE:
			setup.alg_type = WD_ZLIB;
			setup.win_sz = WD_COMP_WS_8K;
			setup.comp_lv = WD_COMP_L8;
			setup.op_type = WD_DIR_COMPRESS;
			param.type = setup.op_type;
			param.numa_id = 0;
			setup.sched_param = &param;
			break;
		default:
			goto err;
		}
		break;
	case RTE_COMP_DECOMPRESS:
		switch (xform->decompress.algo) {
		case RTE_COMP_ALGO_NULL:
			break;
		case RTE_COMP_ALGO_DEFLATE:
			setup.alg_type = WD_ZLIB;
			setup.comp_lv = WD_COMP_L8;
			setup.op_type = WD_DIR_DECOMPRESS;
			param.type = setup.op_type;
			param.numa_id = 0;
			setup.sched_param = &param;
			break;
		default:
			goto err;
		}
		break;
	default:
		UADK_LOG(ERR, "Algorithm %u is not supported.", xform->type);
		goto err;
	}

	handle = wd_comp_alloc_sess(&setup);
	if (!handle)
		goto err;
	stream->handle = handle;
	stream->type = xform->type;
	return 0;
err:
	rte_mempool_put(priv->mp, private_xform);
	return -EINVAL;
}

static int
uadk_compress_pmd_xform_free(struct rte_compressdev *dev __rte_unused, void *private_xform)
{
	struct uadk_stream *stream = (struct uadk_stream *)private_xform;
	struct rte_mempool *mp;

	if (!stream)
		return -EINVAL;

	wd_comp_free_sess(stream->handle);
	memset(stream, 0, sizeof(struct uadk_stream));
	mp = rte_mempool_from_obj(stream);
	rte_mempool_put(mp, stream);
	return 0;
}

static struct rte_compressdev_ops uadk_compress_pmd_ops = {
		.dev_configure		= uadk_compress_pmd_config,
		.dev_start		= uadk_compress_pmd_start,
		.dev_stop		= uadk_compress_pmd_stop,
		.dev_close		= uadk_compress_pmd_close,
		.stats_get		= uadk_compress_pmd_stats_get,
		.stats_reset		= uadk_compress_pmd_stats_reset,
		.dev_infos_get		= uadk_compress_pmd_info_get,
		.queue_pair_setup	= uadk_compress_pmd_qp_setup,
		.queue_pair_release	= uadk_compress_pmd_qp_release,
		.private_xform_create	= uadk_compress_pmd_xform_create,
		.private_xform_free	= uadk_compress_pmd_xform_free,
		.stream_create		= NULL,
		.stream_free		= NULL
};

static uint16_t
uadk_compress_pmd_enqueue_burst_sync(void *queue_pair,
				     struct rte_comp_op **ops, uint16_t nb_ops)
{
	struct uadk_qp *qp = queue_pair;
	struct uadk_stream *stream;
	struct rte_comp_op *op;
	uint16_t enqd = 0;
	int i, ret = 0;

	for (i = 0; i < nb_ops; i++) {
		op = ops[i];

		if (op->op_type == RTE_COMP_OP_STATEFUL) {
			op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		} else {
			/* process stateless ops */
			stream = (struct uadk_stream *)op->private_xform;
			if (stream) {
				struct wd_comp_req req = {0};
				uint16_t dst_len = rte_pktmbuf_data_len(op->m_dst);

				req.src = rte_pktmbuf_mtod(op->m_src, uint8_t *);
				req.src_len = op->src.length;
				req.dst = rte_pktmbuf_mtod(op->m_dst, uint8_t *);
				req.dst_len = dst_len;
				req.op_type = stream->type;
				req.cb = NULL;
				req.data_fmt = WD_FLAT_BUF;
				do {
					ret = wd_do_comp_sync(stream->handle, &req);
				} while (ret == -WD_EBUSY);

				op->consumed += req.src_len;

				if (req.dst_len <= dst_len) {
					op->produced += req.dst_len;
					op->status = RTE_COMP_OP_STATUS_SUCCESS;
				} else  {
					op->status = RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED;
				}

				if (ret) {
					op->status = RTE_COMP_OP_STATUS_ERROR;
					break;
				}
			} else {
				op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
			}
		}

		/* Whatever is out of op, put it into completion queue with
		 * its status
		 */
		if (!ret)
			ret = rte_ring_enqueue(qp->processed_pkts, (void *)op);

		if (unlikely(ret)) {
			/* increment count if failed to enqueue op*/
			qp->qp_stats.enqueue_err_count++;
		} else {
			qp->qp_stats.enqueued_count++;
			enqd++;
		}
	}
	return enqd;
}

static uint16_t
uadk_compress_pmd_dequeue_burst_sync(void *queue_pair,
				     struct rte_comp_op **ops,
				     uint16_t nb_ops)
{
	struct uadk_qp *qp = queue_pair;
	unsigned int nb_dequeued = 0;

	nb_dequeued = rte_ring_dequeue_burst(qp->processed_pkts,
			(void **)ops, nb_ops, NULL);
	qp->qp_stats.dequeued_count += nb_dequeued;

	return nb_dequeued;
}

static int
uadk_compress_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			struct rte_pci_device *pci_dev)
{
	char name[RTE_COMPRESSDEV_NAME_MAX_LEN];
	struct rte_compressdev *compressdev;
	struct rte_compressdev_pmd_init_params init_params = {
		"",
		rte_socket_id(),
	};

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));
	compressdev = rte_compressdev_pmd_create(name, &pci_dev->device,
			sizeof(struct uadk_compress_priv), &init_params);
	if (compressdev == NULL) {
		UADK_LOG(ERR, "driver %s: create failed", init_params.name);
		return -ENODEV;
	}

	compressdev->dev_ops = &uadk_compress_pmd_ops;
	compressdev->dequeue_burst = uadk_compress_pmd_dequeue_burst_sync;
	compressdev->enqueue_burst = uadk_compress_pmd_enqueue_burst_sync;
	compressdev->feature_flags = RTE_COMPDEV_FF_HW_ACCELERATED;

	return 0;
}

static int
uadk_compress_pci_remove(struct rte_pci_device *pci_dev)
{
	struct rte_compressdev *compressdev;
	char name[RTE_COMPRESSDEV_NAME_MAX_LEN];

	if (pci_dev == NULL)
		return -EINVAL;

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));
	compressdev = rte_compressdev_pmd_get_named_dev(name);
	if (compressdev == NULL)
		return -ENODEV;

	return rte_compressdev_pmd_destroy(compressdev);
}

#define PCI_VENDOR_ID_HUAWEI            0x19e5
#define PCI_DEVICE_ID_ZIP_PF            0xa250
#define PCI_DEVICE_ID_ZIP_VF            0xa251

static struct rte_pci_id pci_id_uadk_compress_table[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, PCI_DEVICE_ID_ZIP_PF),
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, PCI_DEVICE_ID_ZIP_VF),
	},
	{
		.device_id = 0
	},
};

/**
 * Structure that represents a PCI driver
 */
static struct rte_pci_driver uadk_compress_pmd = {
	.id_table    = pci_id_uadk_compress_table,
	.probe       = uadk_compress_pci_probe,
	.remove      = uadk_compress_pci_remove,
};

RTE_PMD_REGISTER_PCI(UADK_COMPRESS_DRIVER_NAME, uadk_compress_pmd);
RTE_PMD_REGISTER_PCI_TABLE(UADK_COMPRESS_DRIVER_NAME, pci_id_uadk_compress_table);
