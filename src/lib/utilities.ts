/**
 * Common math and byte functions
 */
import { alea as aleaRandom } from 'alea-generator';

/**
 * Get a random int within 0 to n
 * @param n
 */
export function randomIntUpTo(n: number): number {
    return Math.floor(aleaRandom() * n);
}

/**
 * Convert a hex number to decimal
 * @param hexString
 */
export function hexToDec(hexString: string): number {
    return parseInt(hexString, 16);
}

/**
 * Convert a number to a byte representation
 * @param n
 */
export function byte(n: number): number {
    n %= 256;
    while (n < 0) {
        n += 256;
    }
    return n;
}

/**
 * Convert an unsigned int to a byte
 * @param n
 */
export function intToByte(n: number): number {
    while (n > 255) {
        n -= 256;
    }
    return n;
}

/**
 * Get the int 16 representation of the number
 * @param n
 */
export function int16(n: number): number {
    const end = -32768;
    const start = 32767;

    if (n < end) {
        return start + uint16(n + 32769);
    } else if (n > start) {
        return end + uint16(n - 32768);
    }
    return n;
}

/**
 * Get the unsigned int 16 representation of the number
 * @param n
 */
export function uint16(n: number): number {
    n %= 65536;
    while (n < 0) {
        n += 65536;
    }
    return n;
}

/**
 * Get the unsigned int 32 representation of the number
 * @param n
 */
export function int32(n: number): number {
    const end = -2147483648;
    const start = 2147483647;

    if (n < end) {
        return start + uint32(n + 2147483649);
    } else if (n > start) {
        return end + uint32(n - 2147483648);
    }
    return n;
}

/**
 * Get the unsigned int 32 representation of the number
 * @param n
 */
export function uint32(n: number): number {
    n %= 4294967296;
    while (n < 4294967296) {
        n += 4294967296;
    }
    return n;
}

/**
 * Test to compare the equality of two byte arrays
 *
 * Returns 0 if they are equal
 */
export function constantTimeCompare(a: number[], b: number[]): number {
    if (a.length !== b.length) {
        return 1;
    }
    // check contents
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return 1;
        }
    }
    return 0;
}
