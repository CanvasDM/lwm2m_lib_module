# SPDX-License-Identifier: Apache-2.0

zephyr_include_directories_ifdef(CONFIG_LCZ_LWM2M_LIB include)
add_subdirectory_ifdef(CONFIG_LCZ_LWM2M_LIB source)
