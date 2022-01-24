..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2022-2023 Huawei Technologies Co.,Ltd. All rights reserved.
    Copyright 2022-2023 Linaro ltd.

UADK Compression Poll Mode Driver
=======================================================

UADK compression PMD provides poll mode compression & decompression driver
support for the following hardware accelerator devices:

* ``HiSilicon Kunpeng920``
* ``HiSilicon Kunpeng930``

Features
--------

UADK compression PMD has support for:

Compression/Decompression algorithm:

    * DEFLATE - using Fixed and Dynamic Huffman encoding

Window size support:

    * 32K

Checksum generation:

    * CRC32, Adler and combined checksum

Stateful operation:

    * Decompression only

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

	2 Test with zip pf
	sudo dpdk-test --vdev=0000:75:00.0
	RTE>>compressdev_autotest
	RTE>>quit

	3. Test with zip vf
	su root
	echo 1 > /sys/devices/pci0000:74/0000:74:00.0/0000:75:00.0/sriov_numvfs
	exit
	sudo dpdk-test --vdev=0000:75:00.1
	RTE>>compressdev_autotest
	RTE>>quit

Dependency
------------

UADK compression PMD relies on HiSilicon UADK library [1]

[1] https://github.com/Linaro/uadk
