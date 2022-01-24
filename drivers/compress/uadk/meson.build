# SPDX-License-Identifier: BSD-3-Clause
# Copyright 2022-2023 Huawei Technologies Co.,Ltd. All rights reserved.
# Copyright 2022-2023 Linaro ltd.

if not is_linux
    build = false
    reason = 'only supported on Linux'
    subdir_done()
endif

if arch_subdir != 'arm' or not dpdk_conf.get('RTE_ARCH_64')
    build = false
    reason = 'only supported on aarch64'
    subdir_done()
endif

sources = files(
        'uadk_compress_pmd.c',
)

deps += ['bus_pci']
dep = cc.find_library('libwd_comp', dirs: ['/usr/local/lib'], required: false)
if not dep.found()
	build = false
	reason = 'missing dependency, "libwd_comp"'
else
	ext_deps += dep
endif
