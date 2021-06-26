#!bin/bash
#
# Copyright 2021 Sony Group Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

cidir=$(dirname "$0")
source "${cidir}/lib.sh"

clone_tests_repo

pushd ${tests_repo_dir}
.ci/install_libseccomp.sh
popd
