/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022-2023 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2022-2023 Linaro ltd.
 */

#include <rte_bus_pci.h>
#include <rte_comp.h>
#include <cryptodev_pmd.h>
#include <uadk/wd_cipher.h>
#include <uadk/wd_digest.h>
#include <uadk/wd_sched.h>

struct uadk_crypto_priv {
	bool env_cipher_init;
	bool env_auth_init;
	bool env_aead_init;
	struct uacce_dev *udev;
} __rte_cache_aligned;

struct uadk_qp {
	struct rte_ring *processed_pkts;
	/**< Ring for placing process packets */
	struct rte_cryptodev_stats qp_stats;
	/**< Queue pair statistics */
	uint16_t id;
	/**< Queue Pair Identifier */
	char name[RTE_CRYPTODEV_NAME_MAX_LEN];
	/**< Unique Queue Pair Name */
} __rte_cache_aligned;

enum uadk_chain_order {
	UADK_CHAIN_ONLY_CIPHER,
	UADK_CHAIN_ONLY_AUTH,
	UADK_CHAIN_CIPHER_BPI,
	UADK_CHAIN_CIPHER_AUTH,
	UADK_CHAIN_AUTH_CIPHER,
	UADK_CHAIN_COMBINED,
	UADK_CHAIN_NOT_SUPPORTED
};

struct uadk_crypto_session {
	handle_t handle_cipher;
	handle_t handle_digest;
	enum uadk_chain_order chain_order;
	struct wd_cipher_req req;

	struct {
		uint16_t length;
		uint16_t offset;
	} iv;
	/**< IV parameters */

	/** Cipher Parameters */
	struct {
		enum rte_crypto_cipher_operation direction;
		/**< cipher operation direction */

		struct {
			uint8_t data[256];
			/**< key data */
			size_t length;
			/**< key length in bytes */
		} key;
	} cipher;

	/** Authentication Parameters */
	struct {
		struct wd_digest_req req;
	} auth;
} __rte_cache_aligned;

static uint8_t uadk_cryptodev_driver_id;

RTE_LOG_REGISTER_DEFAULT(uadk_crypto_logtype, INFO);

#define UADK_LOG(level, fmt, ...)  \
	rte_log(RTE_LOG_ ## level, uadk_crypto_logtype,  \
			"%s() line %u: " fmt "\n", __func__, __LINE__,  \
					## __VA_ARGS__)

static const struct rte_cryptodev_capabilities uadk_crypto_920_capabilities[] = {
	{	/* MD5 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_MD5,
				.block_size = 64,
				.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				},
			}, }
		}, }
	},
	{	/* SHA1 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA1,
				.block_size = 64,
				.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 20,
					.max = 20,
					.increment = 0
				},
			}, }
		}, }
	},
	{	/* SHA224 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA224,
				.block_size = 64,
					.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 28,
					.max = 28,
					.increment = 0
				},
			}, }
		}, }
	},
	{	/* SHA256 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA256,
				.block_size = 64,
				.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 32,
					.max = 32,
					.increment = 0
				},
			}, }
		}, }
	},
	{	/* SHA384 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA384,
				.block_size = 64,
				.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 48,
					.max = 48,
					.increment = 0
					},
			}, }
		}, }
	},
	{	/* SHA512 */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_AUTH,
			{.auth = {
				.algo = RTE_CRYPTO_AUTH_SHA512,
				.block_size = 128,
				.key_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				},
				.digest_size = {
					.min = 64,
					.max = 64,
					.increment = 0
				},
			}, }
		}, }
	},
	{	/* AES ECB */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_ECB,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 8
				},
				.iv_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* AES CBC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_CBC,
				.block_size = 16,
				.key_size = {
					.min = 16,
					.max = 32,
					.increment = 8
				},
				.iv_size = {
					.min = 16,
					.max = 16,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* AES XTS */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_AES_XTS,
				.block_size = 1,
				.key_size = {
					.min = 32,
					.max = 64,
					.increment = 32
				},
				.iv_size = {
					.min = 0,
					.max = 0,
					.increment = 0
				}
			}, }
		}, }
	},
	{	/* DES CBC */
		.op = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		{.sym = {
			.xform_type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			{.cipher = {
				.algo = RTE_CRYPTO_CIPHER_DES_CBC,
				.block_size = 8,
				.key_size = {
					.min = 8,
					.max = 8,
					.increment = 0
				},
				.iv_size = {
					.min = 8,
					.max = 8,
					.increment = 0
				}
			}, }
		}, }
	},
	/* End of symmetric capabilities */
	RTE_CRYPTODEV_END_OF_CAPABILITIES_LIST()
};

/** Configure device */
static int
uadk_crypto_pmd_config(struct rte_cryptodev *dev __rte_unused,
		       struct rte_cryptodev_config *config __rte_unused)
{
	return 0;
}

/** Start device */
static int
uadk_crypto_pmd_start(struct rte_cryptodev *dev __rte_unused)
{
	return 0;
}

/** Stop device */
static void
uadk_crypto_pmd_stop(struct rte_cryptodev *dev __rte_unused)
{
}

/** Close device */
static int
uadk_crypto_pmd_close(struct rte_cryptodev *dev)
{
	struct uadk_crypto_priv *priv = dev->data->dev_private;

	if (priv->env_cipher_init) {
		wd_cipher_env_uninit();
		priv->env_cipher_init = false;
	}

	if (priv->env_auth_init) {
		wd_digest_env_uninit();
		priv->env_auth_init = false;
	}

	return 0;
}

/** Get device statistics */
static void
uadk_crypto_pmd_stats_get(struct rte_cryptodev *dev,
			  struct rte_cryptodev_stats *stats)
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

/** Reset device statistics */
static void
uadk_crypto_pmd_stats_reset(struct rte_cryptodev *dev __rte_unused)
{
	int qp_id;

	for (qp_id = 0; qp_id < dev->data->nb_queue_pairs; qp_id++) {
		struct uadk_qp *qp = dev->data->queue_pairs[qp_id];

		memset(&qp->qp_stats, 0, sizeof(qp->qp_stats));
	}
}

/** Get device info */
static void
uadk_crypto_pmd_info_get(struct rte_cryptodev *dev,
			 struct rte_cryptodev_info *dev_info)
{
	struct uadk_crypto_priv *priv = dev->data->dev_private;

	if (dev_info != NULL) {
		dev_info->driver_id = dev->driver_id;
		dev_info->driver_name = dev->device->driver->name;
		dev_info->max_nb_queue_pairs = 128;
		/* No limit of number of sessions */
		dev_info->sym.max_nb_sessions = 0;
		dev_info->feature_flags = dev->feature_flags;

		if (priv->udev && !strcmp(priv->udev->api, "hisi_qm_v2"))
			dev_info->capabilities = uadk_crypto_920_capabilities;
	}
}

/** Release queue pair */
static int
uadk_crypto_pmd_qp_release(struct rte_cryptodev *dev, uint16_t qp_id)
{
	struct uadk_qp *qp = dev->data->queue_pairs[qp_id];

	if (qp) {
		rte_ring_free(qp->processed_pkts);
		rte_free(qp);
		dev->data->queue_pairs[qp_id] = NULL;
	}
	return 0;
}

/** set a unique name for the queue pair based on its name, dev_id and qp_id */
static int
uadk_pmd_qp_set_unique_name(struct rte_cryptodev *dev,
			    struct uadk_qp *qp)
{
	unsigned int n = snprintf(qp->name, sizeof(qp->name),
				  "uadk_crypto_pmd_%u_qp_%u",
				  dev->data->dev_id, qp->id);

	if (n >= sizeof(qp->name))
		return -1;

	return 0;
}

/** Create a ring to place process packets on */
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
uadk_crypto_pmd_qp_setup(struct rte_cryptodev *dev, uint16_t qp_id,
			 const struct rte_cryptodev_qp_conf *qp_conf,
			 int socket_id)
{
	struct uadk_qp *qp;

	/* Free memory prior to re-allocation if needed. */
	if (dev->data->queue_pairs[qp_id] != NULL)
		uadk_crypto_pmd_qp_release(dev, qp_id);

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
			qp_conf->nb_descriptors, socket_id);
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

static unsigned int
uadk_crypto_sym_session_get_size(struct rte_cryptodev *dev __rte_unused)
{
	return sizeof(struct uadk_crypto_session);
}

static enum uadk_chain_order
uadk_get_chain_order(const struct rte_crypto_sym_xform *xform)
{
	enum uadk_chain_order res = UADK_CHAIN_NOT_SUPPORTED;

	if (xform != NULL) {
		if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH) {
			if (xform->next == NULL)
				res = UADK_CHAIN_ONLY_AUTH;
			else if (xform->next->type ==
					RTE_CRYPTO_SYM_XFORM_CIPHER)
				res = UADK_CHAIN_AUTH_CIPHER;
		}

		if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER) {
			if (xform->next == NULL)
				res = UADK_CHAIN_ONLY_CIPHER;
			else if (xform->next->type == RTE_CRYPTO_SYM_XFORM_AUTH)
				res = UADK_CHAIN_CIPHER_AUTH;
		}

		if (xform->type == RTE_CRYPTO_SYM_XFORM_AEAD)
			res = UADK_CHAIN_COMBINED;
	}

	return res;
}

static int
uadk_set_session_cipher_parameters(struct rte_cryptodev *dev,
				   struct uadk_crypto_session *sess,
				   struct rte_crypto_sym_xform *xform)
{
	struct uadk_crypto_priv *priv = dev->data->dev_private;
	struct rte_crypto_cipher_xform *cipher = &xform->cipher;
	struct wd_cipher_sess_setup setup = {0};
	struct sched_params params = {0};
	int ret;

	if (!priv->env_cipher_init) {
		ret = wd_cipher_env_init(NULL);
		if (ret < 0)
			return -EINVAL;
		priv->env_cipher_init = true;
	}

	sess->cipher.direction = cipher->op;
	sess->cipher.key.length = cipher->key.length;
	sess->iv.offset = cipher->iv.offset;
	sess->iv.length = cipher->iv.length;
	rte_memcpy(sess->cipher.key.data, cipher->key.data, cipher->key.length);

	switch (cipher->algo) {
	/* Cover supported cipher algorithms */
	case RTE_CRYPTO_CIPHER_AES_CTR:
		setup.alg = WD_CIPHER_AES;
		setup.mode = WD_CIPHER_CTR;
		break;
	case RTE_CRYPTO_CIPHER_AES_ECB:
		setup.alg = WD_CIPHER_AES;
		setup.mode = WD_CIPHER_ECB;
		break;
	case RTE_CRYPTO_CIPHER_AES_CBC:
		setup.alg = WD_CIPHER_AES;
		setup.mode = WD_CIPHER_CBC;
		break;
	case RTE_CRYPTO_CIPHER_AES_XTS:
		setup.alg = WD_CIPHER_AES;
		setup.mode = WD_CIPHER_XTS;
		break;
	default:
		return -ENOTSUP;
	}

	params.numa_id = priv->udev->numa_id;
	setup.sched_param = &params;
	sess->handle_cipher = wd_cipher_alloc_sess(&setup);
	if (!sess->handle_cipher) {
		UADK_LOG(ERR, "uadk failed to alloc session!\n");
		return -EINVAL;
	}

	ret = wd_cipher_set_key(sess->handle_cipher, cipher->key.data, cipher->key.length);
	if (ret) {
		wd_cipher_free_sess(sess->handle_cipher);
		UADK_LOG(ERR, "uadk failed to set key!\n");
		return -EINVAL;
	}

	return 0;
}

/* Set session auth parameters */
static int
uadk_set_session_auth_parameters(struct rte_cryptodev *dev,
				 struct uadk_crypto_session *sess,
				 struct rte_crypto_sym_xform *xform)
{
	struct uadk_crypto_priv *priv = dev->data->dev_private;
	struct wd_digest_sess_setup setup = {0};
	struct sched_params params = {0};
	int ret;

	if (!priv->env_auth_init) {
		ret = wd_digest_env_init(NULL);
		if (ret < 0)
			return -EINVAL;
		priv->env_auth_init = true;
	}

	switch (xform->auth.algo) {
	case RTE_CRYPTO_AUTH_MD5:
		setup.mode = WD_DIGEST_NORMAL;
		setup.alg = WD_DIGEST_MD5;
		sess->auth.req.out_buf_bytes = 16;
		sess->auth.req.out_bytes = 16;
		break;
	case RTE_CRYPTO_AUTH_SHA1:
		setup.mode = WD_DIGEST_NORMAL;
		setup.alg = WD_DIGEST_SHA1;
		sess->auth.req.out_buf_bytes = 20;
		sess->auth.req.out_bytes = 20;
		break;
	case RTE_CRYPTO_AUTH_SHA224:
		setup.mode = WD_DIGEST_NORMAL;
		setup.alg = WD_DIGEST_SHA224;
		sess->auth.req.out_buf_bytes = 28;
		sess->auth.req.out_bytes = 28;
		break;
	case RTE_CRYPTO_AUTH_SHA256:
		setup.mode = WD_DIGEST_NORMAL;
		setup.alg = WD_DIGEST_SHA256;
		sess->auth.req.out_buf_bytes = 32;
		sess->auth.req.out_bytes = 32;
		break;
	case RTE_CRYPTO_AUTH_SHA384:
		setup.mode = WD_DIGEST_NORMAL;
		setup.alg = WD_DIGEST_SHA384;
		sess->auth.req.out_buf_bytes = 48;
		sess->auth.req.out_bytes = 48;
		break;
	case RTE_CRYPTO_AUTH_SHA512:
		setup.mode = WD_DIGEST_NORMAL;
		setup.alg = WD_DIGEST_SHA512;
		sess->auth.req.out_buf_bytes = 64;
		sess->auth.req.out_bytes = 64;
		break;
	default:
		return -ENOTSUP;
	}

	params.numa_id = priv->udev->numa_id;
	setup.sched_param = &params;
	sess->handle_digest = wd_digest_alloc_sess(&setup);
	if (!sess->handle_digest) {
		UADK_LOG(ERR, "uadk failed to alloc session!\n");
		return -EINVAL;
	}

	return 0;
}

static int
uadk_crypto_sym_session_configure(struct rte_cryptodev *dev,
				  struct rte_crypto_sym_xform *xform,
				  struct rte_cryptodev_sym_session *session,
				  struct rte_mempool *mp)
{
	struct rte_crypto_sym_xform *cipher_xform = NULL;
	struct rte_crypto_sym_xform *auth_xform = NULL;
	struct rte_crypto_sym_xform *aead_xform __rte_unused = NULL;
	struct uadk_crypto_session *sess;
	int ret;

	ret = rte_mempool_get(mp, (void *)&sess);
	if (ret != 0) {
		UADK_LOG(ERR, "Failed to get session %p private data from mempool",
			 sess);
		return -ENOMEM;
	}

	sess->chain_order = uadk_get_chain_order(xform);
	switch (sess->chain_order) {
	case UADK_CHAIN_ONLY_CIPHER:
		cipher_xform = xform;
		break;
	case UADK_CHAIN_ONLY_AUTH:
		auth_xform = xform;
		break;
	case UADK_CHAIN_CIPHER_AUTH:
		cipher_xform = xform;
		auth_xform = xform->next;
		break;
	case UADK_CHAIN_AUTH_CIPHER:
		auth_xform = xform;
		cipher_xform = xform->next;
		break;
	case UADK_CHAIN_COMBINED:
		aead_xform = xform;
		break;
	default:
		ret = -ENOTSUP;
		goto err;
	}

	if (cipher_xform) {
		ret = uadk_set_session_cipher_parameters(dev, sess, cipher_xform);
		if (ret != 0) {
			UADK_LOG(ERR,
				"Invalid/unsupported cipher parameters");
			goto err;
		}
	}

	if (auth_xform) {
		ret = uadk_set_session_auth_parameters(dev, sess, auth_xform);
		if (ret != 0)
			goto err;
	}

	set_sym_session_private_data(session, dev->driver_id, sess);
	return 0;
err:
	rte_mempool_put(mp, sess);
	return ret;
}

static void
uadk_crypto_sym_session_clear(struct rte_cryptodev *dev,
			      struct rte_cryptodev_sym_session *sess)
{
	struct uadk_crypto_session *priv_sess =
			get_sym_session_private_data(sess, dev->driver_id);

	if (unlikely(priv_sess == NULL)) {
		UADK_LOG(ERR, "Failed to get session %p private data.", priv_sess);
		return;
	}

	if (priv_sess->handle_cipher) {
		wd_cipher_free_sess(priv_sess->handle_cipher);
		priv_sess->handle_cipher = 0;
	}

	if (priv_sess->handle_digest) {
		wd_digest_free_sess(priv_sess->handle_digest);
		priv_sess->handle_digest = 0;
	}

	set_sym_session_private_data(sess, dev->driver_id, NULL);
	rte_mempool_put(rte_mempool_from_obj(priv_sess), priv_sess);
}

static struct rte_cryptodev_ops uadk_crypto_pmd_ops = {
		.dev_configure		= uadk_crypto_pmd_config,
		.dev_start		= uadk_crypto_pmd_start,
		.dev_stop		= uadk_crypto_pmd_stop,
		.dev_close		= uadk_crypto_pmd_close,
		.stats_get		= uadk_crypto_pmd_stats_get,
		.stats_reset		= uadk_crypto_pmd_stats_reset,
		.dev_infos_get		= uadk_crypto_pmd_info_get,
		.queue_pair_setup	= uadk_crypto_pmd_qp_setup,
		.queue_pair_release	= uadk_crypto_pmd_qp_release,
		.sym_session_get_size	= uadk_crypto_sym_session_get_size,
		.sym_session_configure	= uadk_crypto_sym_session_configure,
		.sym_session_clear	= uadk_crypto_sym_session_clear
};

static void
uadk_process_cipher_op(struct rte_crypto_op *op,
		       struct uadk_crypto_session *sess,
		       struct rte_mbuf *msrc, struct rte_mbuf *mdst)
{
	struct wd_cipher_req req = {0};
	int ret;

	if (!sess) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}

	req.src = rte_pktmbuf_mtod(msrc, uint8_t *);
	req.in_bytes = op->sym->cipher.data.length;
	req.dst = rte_pktmbuf_mtod(mdst, uint8_t *);
	req.out_buf_bytes = req.in_bytes;
	req.iv_bytes = sess->iv.length;
	req.iv = rte_crypto_op_ctod_offset(op, uint8_t *,
			sess->iv.offset);
	if (sess->cipher.direction == RTE_CRYPTO_CIPHER_OP_ENCRYPT)
		req.op_type = WD_CIPHER_ENCRYPTION;
	else
		req.op_type = WD_CIPHER_DECRYPTION;

	do {
		ret = wd_do_cipher_sync(sess->handle_cipher, &req);
	} while (ret == -WD_EBUSY);

	if (req.out_buf_bytes <= req.in_bytes)
		op->status = RTE_COMP_OP_STATUS_SUCCESS;
	else
		op->status = RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED;

	if (ret)
		op->status = RTE_COMP_OP_STATUS_ERROR;
}

static void
uadk_process_auth_op(struct rte_crypto_op *op,
		     struct uadk_crypto_session *sess,
		     struct rte_mbuf *msrc, struct rte_mbuf *mdst)
{
	int srclen = op->sym->auth.data.length;
	uint8_t *auth_dst;
	int ret;

	auth_dst = op->sym->auth.digest.data;
	if (auth_dst == NULL)
		auth_dst = rte_pktmbuf_mtod_offset(mdst, uint8_t *,
				op->sym->auth.data.offset +
				op->sym->auth.data.length);

	if (!sess) {
		op->status = RTE_COMP_OP_STATUS_INVALID_ARGS;
		return;
	}

	sess->auth.req.in = rte_pktmbuf_mtod(msrc, uint8_t *);
	sess->auth.req.in_bytes = srclen;
	sess->auth.req.out = auth_dst;

	do {
		ret = wd_do_digest_sync(sess->handle_digest, &sess->auth.req);
	} while (ret == -WD_EBUSY);


	if (sess->auth.req.out_buf_bytes <= sess->auth.req.in_bytes)
		op->status = RTE_COMP_OP_STATUS_SUCCESS;
	else
		op->status = RTE_COMP_OP_STATUS_OUT_OF_SPACE_TERMINATED;

	if (ret)
		op->status = RTE_COMP_OP_STATUS_ERROR;
}

static uint16_t
uadk_crypto_enqueue_burst(void *queue_pair, struct rte_crypto_op **ops,
			  uint16_t nb_ops)
{
	struct uadk_qp *qp = queue_pair;
	struct uadk_crypto_session *sess = NULL;
	struct rte_mbuf *msrc, *mdst;
	struct rte_crypto_op *op;
	uint16_t enqd = 0;
	int i, ret;

	for (i = 0; i < nb_ops; i++) {
		op = ops[i];
		msrc = op->sym->m_src;
		mdst = op->sym->m_dst ? op->sym->m_dst : op->sym->m_src;

		if (op->sess_type == RTE_CRYPTO_OP_WITH_SESSION) {
			if (likely(op->sym->session != NULL))
				sess = (struct uadk_crypto_session *)
					get_sym_session_private_data(
						op->sym->session,
						uadk_cryptodev_driver_id);
		}

		switch (sess->chain_order) {
		case UADK_CHAIN_ONLY_CIPHER:
			uadk_process_cipher_op(op, sess, msrc, mdst);
			break;
		case UADK_CHAIN_ONLY_AUTH:
			uadk_process_auth_op(op, sess, msrc, mdst);
			break;
		default:
			op->status = RTE_CRYPTO_OP_STATUS_ERROR;
			break;
		}

		/* Whatever is out of op, put it into completion queue with
		 * its status
		 */
		if (op->status != RTE_CRYPTO_OP_STATUS_ERROR) {
			ret = rte_ring_enqueue(qp->processed_pkts, (void *)op);
			if (ret < 0)
				goto enqueue_err;
			qp->qp_stats.enqueued_count++;
			enqd++;
		} else {
			/* increment count if failed to enqueue op*/
			qp->qp_stats.enqueue_err_count++;
		}
	}
	return enqd;

enqueue_err:
	qp->qp_stats.enqueue_err_count++;
	return enqd;
}

static uint16_t
uadk_crypto_dequeue_burst(void *queue_pair, struct rte_crypto_op **ops,
			  uint16_t nb_ops)
{
	struct uadk_qp *qp = queue_pair;
	unsigned int nb_dequeued;

	nb_dequeued = rte_ring_dequeue_burst(qp->processed_pkts,
			(void **)ops, nb_ops, NULL);
	qp->qp_stats.dequeued_count += nb_dequeued;

	return nb_dequeued;
}

static int
uadk_crypto_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
			struct rte_pci_device *pci_dev)
{
	char name[RTE_CRYPTODEV_NAME_MAX_LEN];
	struct rte_cryptodev *dev;
	struct rte_cryptodev_pmd_init_params init_params = {
		.name = "",
		.private_data_size = sizeof(struct uadk_crypto_priv),
		.max_nb_queue_pairs =
				RTE_CRYPTODEV_PMD_DEFAULT_MAX_NB_QUEUE_PAIRS,
	};
	struct uadk_crypto_priv *priv;
	struct uacce_dev *udev;

	udev = wd_get_accel_dev("cipher");
	if (!udev)
		return -ENODEV;

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	dev = rte_cryptodev_pmd_create(name, &pci_dev->device, &init_params);
	if (dev == NULL) {
		UADK_LOG(ERR, "driver %s: create failed", init_params.name);
		return -ENODEV;
	}

	dev->dev_ops = &uadk_crypto_pmd_ops;
	dev->driver_id = uadk_cryptodev_driver_id;
	dev->dequeue_burst = uadk_crypto_dequeue_burst;
	dev->enqueue_burst = uadk_crypto_enqueue_burst;
	dev->feature_flags = RTE_CRYPTODEV_FF_HW_ACCELERATED |
			     RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			     RTE_CRYPTODEV_FF_SYM_SESSIONLESS;
	priv = dev->data->dev_private;
	priv->udev = udev;

	rte_cryptodev_pmd_probing_finish(dev);
	return 0;
}

static int
uadk_crypto_pci_remove(struct rte_pci_device *pci_dev)
{
	char name[RTE_CRYPTODEV_NAME_MAX_LEN];
	struct uadk_crypto_priv *priv;
	struct rte_cryptodev *dev;

	if (pci_dev == NULL)
		return -EINVAL;

	rte_pci_device_name(&pci_dev->addr, name, sizeof(name));

	dev = rte_cryptodev_pmd_get_named_dev(name);
	if (dev == NULL)
		return -ENODEV;

	priv = dev->data->dev_private;
	free(priv->udev);

	return rte_cryptodev_pmd_destroy(dev);
}

#define PCI_VENDOR_ID_HUAWEI            0x19e5
#define PCI_DEVICE_ID_SEC_PF            0xa255
#define PCI_DEVICE_ID_SEC_VF            0xa256

static struct rte_pci_id pci_id_uadk_crypto_table[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, PCI_DEVICE_ID_SEC_PF),
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, PCI_DEVICE_ID_SEC_VF),
	},
	{
		.device_id = 0
	},
};

/**
 * Structure that represents a PCI driver
 */
static struct rte_pci_driver uadk_crypto_pmd = {
	.id_table    = pci_id_uadk_crypto_table,
	.probe       = uadk_crypto_pci_probe,
	.remove      = uadk_crypto_pci_remove,
};

#define UADK_CRYPTO_DRIVER_NAME crypto_uadk
static struct cryptodev_driver uadk_crypto_drv;

RTE_PMD_REGISTER_PCI(UADK_CRYPTO_DRIVER_NAME, uadk_crypto_pmd);
RTE_PMD_REGISTER_PCI_TABLE(UADK_CRYPTO_DRIVER_NAME, pci_id_uadk_crypto_table);
RTE_PMD_REGISTER_CRYPTO_DRIVER(uadk_crypto_drv, uadk_crypto_pmd.driver,
			       uadk_cryptodev_driver_id);
