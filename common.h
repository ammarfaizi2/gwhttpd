// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef COMMON_H
#define COMMON_H

#ifndef fallthrough
#define fallthrough __attribute__((__fallthrough__))
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef __cold
#define __cold __attribute__((__cold__))
#endif

#ifndef __hot
#define __hot __attribute__((__hot__))
#endif

#include "syscall.h"

#endif /* #ifndef COMMON_H */
