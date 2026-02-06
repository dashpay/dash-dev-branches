# Copyright (c) 2022-2023 The Zcash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

package:=rustcxx
$(package)_version:=$(native_cxxbridge_version)
$(package)_download_path:=$(native_cxxbridge_download_path)
$(package)_file_name:=$(native_cxxbridge_file_name)
$(package)_download_file:=$(native_cxxbridge_download_file)
$(package)_sha256_hash:=$(native_cxxbridge_sha256_hash)

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include/rust && \
  cp include/cxx.h $($(package)_staging_prefix_dir)/include/rust
endef
