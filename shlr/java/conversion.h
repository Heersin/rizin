// SPDX-License-Identifier: Apache-2.0
#ifndef JAVA_CONVERSION_H
#define JAVA_CONVERSION_H

#include <rz_types.h>
#define f32 float
#define f64 double

#define raw_to_ushort(x, y) ((ut16)(((0xff & x[y + 1]) | ((x[y] & 0xff) << 8)) & 0xffff))
#define raw_to_uint(x, y)   ((ut32)(((x[y] & 0xff) << 24) | ((x[y + 1] & 0xff) << 16) | ((x[y + 2] & 0xff) << 8) | (x[y + 3] & 0xff)))
#define raw_to_float(x, y)    ((f32)raw_to_uint(x, y))
#define raw_to_long(x, y)   (((ut64)raw_to_uint(x, y) << 32) | ((ut64)raw_to_uint(x, y + 4) & 0xffffffff))

double raw_to_double(const ut8 *raw, ut64 offset);

#endif /* JAVA_CONVERSION_H */
