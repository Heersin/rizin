#include "conversion.h"

static double custom_pow(ut64 base, int exp) {
	ut8 flag = 0;
	ut64 res = 1;
	if (exp < 0) {
		flag = 1;
		exp *= -1;
	}
	while (exp) {
		if (exp & 1) {
			res *= base;
		}
		exp >>= 1;
		base *= base;
		// eprintf("Result: %" PFMT64d ", base: %" PFMT64d ", exp: %d\n", res, base, exp);
	}
	if (flag == 0) {
		return 1.0 * res;
	}
	return (1.0 / res);
}

double raw_to_double(const ut8 *raw, ut64 offset) {
	ut64 bits = raw_to_long(raw, offset);
	int s = ((bits >> 63) == 0) ? 1 : -1;
	int e = (int)((bits >> 52) & 0x7ffL);
	long m = (e == 0) ? (bits & 0xfffffffffffffLL) << 1 : (bits & 0xfffffffffffffLL) | 0x10000000000000LL;
	double res = 0.0;
	// eprintf("Convert Long to Double: %08" PFMT64x "\n", bits);
	if (bits == 0x7ff0000000000000LL) {
		return INFINITY;
	}
	if (bits == 0xfff0000000000000LL) {
		return -INFINITY;
	}
	if (0x7ff0000000000001LL <= bits && bits <= 0x7fffffffffffffffLL) {
		return NAN;
	}
	if (0xfff0000000000001LL <= bits && bits <= 0xffffffffffffffffLL) {
		return NAN;
	}
	res = s * m * custom_pow(2, e - 1075); // XXXX TODO Get double to work correctly here
	// eprintf("	High-bytes = %02x %02x %02x %02x\n", raw[0], raw[1], raw[2], raw[3]);
	// eprintf("	Low-bytes = %02x %02x %02x %02x\n", raw[4], raw[5], raw[6], raw[7]);
	// eprintf("Convert Long to Double s: %d, m: 0x%08lx, e: 0x%08x, res: %f\n", s, m, e, res);
	return res;
}
