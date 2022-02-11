..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2022-2023 Huawei Technologies Co.,Ltd. All rights reserved.
    Copyright 2022-2023 Linaro ltd.

UADK Crypto Poll Mode Driver
=======================================================

UADK crypto PMD provides poll mode driver
support for the following hardware accelerator devices:

* ``HiSilicon Kunpeng920``
* ``HiSilicon Kunpeng930``

Features
--------

UADK crypto PMD has support for:

Cipher algorithms:

* ``RTE_CRYPTO_CIPHER_AES128_CBC``
* ``RTE_CRYPTO_CIPHER_AES192_CBC``
* ``RTE_CRYPTO_CIPHER_AES256_CBC``
* ``RTE_CRYPTO_CIPHER_AES_XTS``

Hash algorithms:

* ``RTE_CRYPTO_AUTH_SHA1``
* ``RTE_CRYPTO_AUTH_SHA224``
* ``RTE_CRYPTO_AUTH_SHA256``
* ``RTE_CRYPTO_AUTH_SHA384``
* ``RTE_CRYPTO_AUTH_SHA512``

Supported AEAD algorithms:

* ``RTE_CRYPTO_AEAD_AES_GCM``
* ``RTE_CRYPTO_AEAD_AES_CCM``

Test steps
-----------

   .. code-block:: console

	1. Build
	cd dpdk
	mkdir build
	meson build (--reconfigure)
	cd build
	ninja
	sudo ninja install

	2. Prepare
	echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
	echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
	echo 1024 > /sys/devices/system/node/node2/hugepages/hugepages-2048kB/nr_hugepages
	echo 1024 > /sys/devices/system/node/node3/hugepages/hugepages-2048kB/nr_hugepages
	mkdir -p /mnt/huge_2mb
	mount -t hugetlbfs none /mnt/huge_2mb -o pagesize=2MB

	2 Test with crypto pf
	sudo dpdk-test --vdev=0000:76:00.0 (--log-level=6)
	RTE>>cryptodev_uadk_autotest
	RTE>>quit

	3. Test with crypto vf
	su root
	echo 1 > /sys/devices/pci0000:74/0000:74:00.0/0000:76:00.0/sriov_numvfs
	exit
	sudo dpdk-test --vdev=0000:76:00.1
	RTE>>cryptodev_uadk_autotest
	RTE>>quit

Dependency
------------

UADK crypto PMD relies on HiSilicon UADK library [1]

[1] https://github.com/Linaro/uadk
