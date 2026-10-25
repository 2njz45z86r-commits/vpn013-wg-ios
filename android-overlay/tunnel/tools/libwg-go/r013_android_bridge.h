/* SPDX-License-Identifier: MIT */
#pragma once
#include <stdint.h>
int r013_gate_prepare(uint64_t gate, int route, int fd);
void r013_gate_release(uint64_t gate);
