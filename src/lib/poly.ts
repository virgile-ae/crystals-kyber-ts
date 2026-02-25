import { byte, int16, int32, intToByte, uint16, uint32 } from "./utilities";
import { Buffer } from "buffer";
import { SHAKE } from "sha3";
import { barrettReduce, montgomeryReduce, generateCBDPoly, modQMulMont } from "./byte-ops";
import { KyberService } from "../services/kyber.service";

export class Poly {

    constructor(public paramsK: number) { }

    /**
     * Applies the inverse number-theoretic transform (NTT) to all elements of a
     * vector of polynomials and multiplies by Montgomery factor 2^16
     * @param r
     */
    public polyVectorInvNTTMont(r: number[][]): number[][] {
        for (let i: number = 0; i < this.paramsK; i++) {
            r[i] = this.polyInvNTTMont(r[i]);
        }
        return r;

    }

    /**
     * Applies Barrett reduction to each coefficient of each element of a vector
     * of polynomials.
     *
     * @param r
     * @return
     */
    public polyVectorReduce(r: number[][]): number[][] {
        for (let i = 0; i < this.paramsK; i++) {
            r[i] = this.polyReduce(r[i]);
        }
        return r;
    }

    /**
     * Computes an in-place inverse of a negacyclic number-theoretic transform
     * (NTT) of a polynomial
     *
     * Input is assumed bit-revered order
     *
     * Output is assumed normal order
     *
     * @param r
     * @return
     */
    public polyInvNTTMont(r: number[]): number[] {
        return this.invNTT(r);
    }


    /**
     * Applies forward number-theoretic transforms (NTT) to all elements of a
     * vector of polynomial
     *
     * @param r
     * @return
     */
    public polyVectorNTT(r: number[][]): number[][] {
        for (let i = 0; i < this.paramsK; i++) {
            r[i] = this.ntt(r[i]);
        }
        return r;
    }


    /**
     * Deserialize a byte array into a polynomial vector
     *
     * @param a
     * @return
     */
    public polyVectorFromBytes(a: number[]): number[][] {
        const r = new Array<number[]>(this.paramsK);
        for (let i = 0; i < this.paramsK; i++) {
            const start = (i * KyberService.paramsPolyBytes);
            const end = (i + 1) * KyberService.paramsPolyBytes;
            r[i] = this.polyFromBytes(a.slice(start, end));
        }
        return r;
    }

    /**
     * Serialize a polynomial in to an array of bytes
     *
     * @param a
     * @return
     */
    public polyToBytes(a: number[]): number[] {
        const r = new Array<number>(KyberService.paramsPolyBytes);
        const a2 = this.polyConditionalSubQ(a);
        for (let i = 0; i < KyberService.paramsN / 2; i++) {
            const t0 = uint16(a2[2 * i]);
            const t1 = uint16(a2[2 * i + 1]);
            r[3 * i] = byte(t0);
            r[3 * i + 1] = byte(t0 >> 8) | byte(t1 << 4);
            r[3 * i + 2] = byte(t1 >> 4);
        }
        return r;
    }

    /**
     * Check the 0xFFF
     * @param a
     */
    public polyFromBytes(a: number[]): number[] {
        const r = new Array<number>(KyberService.paramsPolyBytes);
        for (let i = 0; i < KyberService.paramsN / 2; i++) {
            r[2 * i] = int16((uint16(a[3 * i]) | (uint16(a[3 * i + 1]) << 8)) & 0xFFF);
            r[2 * i + 1] = int16(((uint16(a[3 * i + 1]) >> 4) | (uint16(a[3 * i + 2]) << 4)) & 0xFFF);
        }
        return r;
    }

    /**
     * Convert a polynomial to a 32-byte message
     *
     * @param a
     * @return
     */
    public polyToMsg(a: number[]): number[] {
        const message = new Array<number>(32).fill(0);
        const a2 = this.polyConditionalSubQ(a);
        for (let i = 0; i < KyberService.paramsN / 8; i++) {
            for (let j = 0; j < 8; j++) {
                const t = (((uint16(a2[8 * i + j]) << 1) + uint16(KyberService.paramsQ / 2)) / uint16(KyberService.paramsQ)) & 1;
                message[i] |= byte(t << j);
            }
        }
        return message;
    }

    /**
     * Convert a 32-byte message to a polynomial
     *
     * @param message
     * @return
     */
    public polyFromData(message: number[]): number[] {
        const r = new Array<number>(KyberService.paramsPolyBytes).fill(0);
        for (let i = 0; i < KyberService.paramsN / 8; i++) {
            for (let j = 0; j < 8; j++) {
                const mask = -int16((message[i] >> j) & 1);
                r[8 * i + j] = mask & int16((KyberService.paramsQ + 1) / 2);
            }
        }
        return r;
    }

    /**
     * Generate a deterministic noise polynomial from a seed and nonce
     *
     * The polynomial output will be close to a centered binomial distribution
     *
     * @param seed
     * @param nonce
     * @param paramsK
     * @return
     */
    public getNoisePoly(seed: number[], nonce: number, paramsK: number): number[] {
        const l = paramsK === 2 ?
            KyberService.paramsETAK512 * KyberService.paramsN / 4 :
            KyberService.paramsETAK768K1024 * KyberService.paramsN / 4;
        const p = this.generatePRFByteArray(l, seed, nonce);
        return generateCBDPoly(p, paramsK);
    }

    /**
     * Pseudo-random function to derive a deterministic array of random bytes
     * from the supplied secret key object and other parameters.
     *
     * @param l
     * @param key
     * @param nonce
     * @return
     */
    public generatePRFByteArray(l: number, key: number[], nonce: number): Buffer {
        const bufString = new SHAKE(256)
            .update(Buffer.from(key))
            .update(Buffer.from([nonce]))
            .digest({ format: "binary", buffer: Buffer.alloc(l) });
        const buf = Buffer.alloc(bufString.length);
        for (let i = 0; i < bufString.length; ++i) {
            buf[i] = +bufString[i];
        }
        return buf;
    }

    /**
     * Perform an in-place number-theoretic transform (NTT)
     *
     * Input is in standard order
     *
     * Output is in bit-reversed order
     *
     * @param r
     * @return
     */
    public ntt(r: number[]): number[] {
        let j = 0;
        let k = 1;
        for (let l = 128; l >= 2; l >>= 1) {
            for (let start = 0; start < 256; start = j + l) {
                const zeta = KyberService.nttZetas[k];
                k++;
                for (j = start; j < start + l; j++) {
                    const t = modQMulMont(zeta, r[j + l]); // t is mod q
                    r[j + l] = int16(r[j] - t);
                    r[j] = int16(r[j] + t);
                }
            }
        }
        return r;
    }

    /**
     * Apply Barrett reduction to all coefficients of this polynomial
     *
     * @param r
     * @return
     */
    public polyReduce(r: number[]): number[] {
        for (let i = 0; i < KyberService.paramsN; i++) {
            r[i] = barrettReduce(r[i]);
        }
        return r;
    }

    /**
     * Performs an in-place conversion of all coefficients of a polynomial from
     * the normal domain to the Montgomery domain
     *
     * @param polyR
     * @return
     */
    public polyToMont(r: number[]): number[] {
        for (let i = 0; i < KyberService.paramsN; i++) {
            r[i] = montgomeryReduce(int32(r[i]) * int32(1353));
        }
        return r;
    }

    /**
     * Pointwise-multiplies elements of the given polynomial-vectors ,
     * accumulates the results , and then multiplies by 2^-16
     *
     * @param a
     * @param b
     * @return
     */
    public polyVectorPointWiseAccMont(a: number[][], b: number[][]): number[] {
        let r = this.polyBaseMulMont(a[0], b[0]);
        for (let i = 1; i < this.paramsK; i++) {
            const t = this.polyBaseMulMont(a[i], b[i]);
            r = this.polyAdd(r, t);
        }
        return this.polyReduce(r);
    }

    /**
     * Multiply two polynomials in the number-theoretic transform (NTT) domain
     *
     * @param a
     * @param b
     * @return
     */
    public polyBaseMulMont(a: number[], b: number[]): number[] {
        for (let i = 0; i < KyberService.paramsN / 4; i++) {
            const rx = this.nttBaseMuliplier(
                a[4 * i], a[4 * i + 1],
                b[4 * i], b[4 * i + 1],
                KyberService.nttZetas[64 + i]
            );
            const ry = this.nttBaseMuliplier(
                a[4 * i + 2], a[4 * i + 3],
                b[4 * i + 2], b[4 * i + 3],
                -KyberService.nttZetas[64 + i]
            );

            a[4 * i] = rx[0];
            a[4 * i + 1] = rx[1];
            a[4 * i + 2] = ry[0];
            a[4 * i + 3] = ry[1];
        }
        return a;
    }

    /**
     * Performs the multiplication of polynomials
     *
     * @param a0
     * @param a1
     * @param b0
     * @param b1
     * @param zeta
     * @return
     */
    public nttBaseMuliplier(a0: number, a1: number, b0: number, b1: number, zeta: number): [number, number] {
        return [
            modQMulMont(modQMulMont(a1, b1), zeta) + modQMulMont(a0, b0),
            modQMulMont(a0, b1) + modQMulMont(a1, b0),
        ];
    }

    /**
     * Add two polynomial vectors
     *
     * @param a
     * @param b
     * @return
     */
    public polyVectorAdd(a: number[][], b: number[][]): number[][] {
        for (let i = 0; i < this.paramsK; i++) {
            a[i] = this.polyAdd(a[i], b[i]);
        }
        return a;
    }

    /**
     * Add two polynomials
     *
     * @param a
     * @param b
     * @return
     */
    public polyAdd(a: number[], b: number[]): number[] {
        let c = new Array(a.length);
        for (let i = 0; i < KyberService.paramsN; i++) {
            c[i] = a[i] + b[i];
        }
        return c;
    }

    /**
     * Subtract two polynomials
     *
     * @param a
     * @param b
     * @return
     */
    public subtract(a: number[], b: number[]): number[] {
        for (let i = 0; i < KyberService.paramsN; i++) {
            a[i] -= b[i];
        }
        return a;
    }

    /**
     * Perform an in-place inverse number-theoretic transform (NTT)
     *
     * Input is in bit-reversed order
     *
     * Output is in standard order
     *
     * @param r
     * @return
     */
    public invNTT(r: number[]): number[] {
        let j = 0;
        let k = 0;
        for (let l = 2; l <= 128; l <<= 1) {
            for (let start = 0; start < 256; start = j + l) {
                const zeta = KyberService.nttZetasInv[k];
                k++;
                for (j = start; j < start + l; j++) {
                    const t = r[j];
                    r[j] = barrettReduce(t + r[j + l]);
                    r[j + l] = t - r[j + l];
                    r[j + l] = modQMulMont(zeta, r[j + l]);
                }
            }
        }
        for (j = 0; j < 256; j++) {
            r[j] = modQMulMont(r[j], KyberService.nttZetasInv[127]);
        }
        return r;
    }

    /**
     * Perform a lossly compression and serialization of a vector of polynomials
     *
     * @param a
     * @param paramsK
     * @return
     */
    public compressPolyVector(a: number[][]): number[] {
        a = this.polyVectorCSubQ(a);
        let rr = 0;
        let r: number[] = [];
        let t: number[] = [];

        if (this.paramsK === 2 || this.paramsK === 3) {
            for (let i = 0; i < this.paramsK; i++) {
                for (let j = 0; j < KyberService.paramsN / 4; j++) {
                    for (let k = 0; k < 4; k++) {
                        t[k] = (((a[i][4 * j + k] << 10) + KyberService.paramsQ / 2) / KyberService.paramsQ) & 0b1111111111;
                    }
                    r[rr] = byte(t[0]);
                    r[rr + 1] = byte(byte(t[0] >> 8) | byte(t[1] << 2));
                    r[rr + 2] = byte(byte(t[1] >> 6) | byte(t[2] << 4));
                    r[rr + 3] = byte(byte(t[2] >> 4) | byte(t[3] << 6));
                    r[rr + 4] = byte((t[3] >> 2));
                    rr += 5;
                }
            }
            return r;
        }

        for (let i = 0; i < this.paramsK; i++) {
            for (let j = 0; j < KyberService.paramsN / 8; j++) {
                for (let k = 0; k < 8; k++) {
                    t[k] = int32((((int32(a[i][8 * j + k]) << 11) + int32(KyberService.paramsQ / 2)) / int32(KyberService.paramsQ)) & 0x7ff);
                }
                r[rr] = byte(t[0]);
                r[rr + 1] = byte((t[0] >> 8) | (t[1] << 3));
                r[rr + 2] = byte((t[1] >> 5) | (t[2] << 6));
                r[rr + 3] = byte((t[2] >> 2));
                r[rr + 4] = byte((t[2] >> 10) | (t[3] << 1));
                r[rr + 5] = byte((t[3] >> 7) | (t[4] << 4));
                r[rr + 6] = byte((t[4] >> 4) | (t[5] << 7));
                r[rr + 7] = byte((t[5] >> 1));
                r[rr + 8] = byte((t[5] >> 9) | (t[6] << 2));
                r[rr + 9] = byte((t[6] >> 6) | (t[7] << 5));
                r[rr + 10] = byte((t[7] >> 3));
                rr += 11;
            }
        }
        return r;
    }

    /**
     * Performs lossy compression and serialization of a polynomial
     *
     * @param polyA
     * @return
     */
    public compressPoly(polyA: number[]): number[] {
        let rr = 0;
        let r: number[] = [];
        const qDiv2 = (KyberService.paramsQ / 2);

        if (this.paramsK === 2 || this.paramsK === 3) {
            for (let i = 0; i < KyberService.paramsN / 8; i++) {
                const t = new Array<number>(8);
                for (let j = 0; j < 8; j++) {
                    const step1: number = int32((polyA[8 * i + j]) << 4);
                    const step2 = int32((step1 + qDiv2) / (KyberService.paramsQ));
                    t[j] = intToByte(step2 & 15);
                }
                r[rr] = intToByte(t[0] | (t[1] << 4));
                r[rr + 1] = intToByte(t[2] | (t[3] << 4));
                r[rr + 2] = intToByte(t[4] | (t[5] << 4));
                r[rr + 3] = intToByte(t[6] | (t[7] << 4));
                rr += 4;
            }
            return r;
        }

        for (let i = 0; i < KyberService.paramsN / 8; i++) {
            const t = new Array<number>(8);
            for (let j = 0; j < 8; j++) {
                const step1: number = int32((polyA[(8 * i) + j] << 5));
                const step2 = int32((step1 + qDiv2) / (KyberService.paramsQ));
                t[j] = intToByte(step2 & 31);
            }
            r[rr] = intToByte(t[0] | (t[1] << 5));
            r[rr + 1] = intToByte((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
            r[rr + 2] = intToByte((t[3] >> 1) | (t[4] << 4));
            r[rr + 3] = intToByte((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
            r[rr + 4] = intToByte((t[6] >> 2) | (t[7] << 3));
            rr += 5;
        }
        return r;
    }

    /**
     * De-serialize and decompress a vector of polynomials
     *
     * Since the compress is lossy, the results will not be exactly the same as
     * the original vector of polynomials
     *
     * @param a
     * @return
     */
    public decompressPolyVector(a: number[]): number[][] {
        const r = new Array<number[]>(this.paramsK);
        for (let i = 0; i < this.paramsK; i++) {
            r[i] = [];
        }
        let aa = 0;
        if (this.paramsK === 2 || this.paramsK === 3) {
            let ctr = 0;
            for (let i = 0; i < this.paramsK; i++) {
                for (let j = 0; j < (KyberService.paramsN / 4); j++) {
                    const t = [
                        uint16(a[aa]) | (uint16(a[aa + 1]) << 8),
                        (uint16(a[aa + 1]) >> 2) | (uint16(a[aa + 2]) << 6),
                        (uint16(a[aa + 2]) >> 4) | (uint16(a[aa + 3]) << 4),
                        (uint16(a[aa + 3]) >> 6) | (uint16(a[aa + 4]) << 2),
                    ];
                    aa += 5;
                    ctr++;
                    for (let k = 0; k < 4; k++) {
                        r[i][4 * j + k] = (uint32(t[k] & 0x3FF) * KyberService.paramsQ + 512) >> 10;
                    }
                }
            }
            return r;
        }

        for (let i = 0; i < this.paramsK; i++) {
            for (let j = 0; j < KyberService.paramsN / 8; j++) {
                const t = [
                    uint16(a[aa]) | (uint16(a[aa + 1]) << 8),
                    (uint16(a[aa + 1]) >> 3) | (uint16(a[aa + 2]) << 5),
                    (uint16(a[aa + 2]) >> 6) | (uint16(a[aa + 3]) << 2) | (uint16(a[aa + 4]) << 10),
                    (uint16(a[aa + 4]) >> 1) | (uint16(a[aa + 5]) << 7),
                    (uint16(a[aa + 5]) >> 4) | (uint16(a[aa + 6]) << 4),
                    (uint16(a[aa + 6]) >> 7) | (uint16(a[aa + 7]) << 1) | (uint16(a[aa + 8]) << 9),
                    (uint16(a[aa + 8]) >> 2) | (uint16(a[aa + 9]) << 6),
                    (uint16(a[aa + 9]) >> 5) | (uint16(a[aa + 10]) << 3)
                ];
                aa += 11;
                for (let k = 0; k < 8; k++) {
                    r[i][8 * j + k] = (uint32(t[k] & 0x7FF) * KyberService.paramsQ + 1024) >> 11;
                }
            }
        }
        return r;
    }

    /**
     * Applies the conditional subtraction of Q (KyberParams) to each coefficient of
     * each element of a vector of polynomials.
     */
    public polyVectorCSubQ(r: number[][]): number[][] {
        for (let i = 0; i < this.paramsK; i++) {
            r[i] = this.polyConditionalSubQ(r[i]);
        }
        return r;
    }

    /**
     * Apply the conditional subtraction of Q (KyberParams) to each coefficient of a
     * polynomial
     *
     * @param r
     * @return
     */
    public polyConditionalSubQ(r: number[]): number[] {
        for (let i = 0; i < KyberService.paramsN; i++) {
            r[i] -= KyberService.paramsQ;
            r[i] += (r[i] >> 31) & KyberService.paramsQ;
        }
        return r;
    }

    /**
     * De-serialize and decompress a vector of polynomials
     *
     * Since the compress is lossy, the results will not be exactly the same as
     * the original vector of polynomials
     *
     * @param a
     * @return
     */
    public decompressPoly(a: number[]): number[] {
        let r = new Array<number>(384);
        let aa = 0;
        if (this.paramsK === 2 || this.paramsK === 3) {
            for (let i = 0; i < KyberService.paramsN / 2; i++) {
                r[2 * i] = int16((((byte(a[aa]) & 15) * uint32(KyberService.paramsQ)) + 8) >> 4);
                r[2 * i + 1] = int16((((byte(a[aa]) >> 4) * uint32(KyberService.paramsQ)) + 8) >> 4);
                aa++;
            }
            return r;
        }

        for (let i = 0; i < KyberService.paramsN / 8; i++) {
            const t = [
                a[aa],
                byte(a[aa] >> 5) | byte((a[aa + 1] << 3)),
                a[aa + 1] >> 2,
                byte((a[aa + 1] >> 7)) | byte((a[aa + 2] << 1)),
                byte((a[aa + 2] >> 4)) | byte((a[aa + 3] << 4)),
                a[aa + 3] >> 1,
                byte((a[aa + 3] >> 6)) | byte((a[aa + 4] << 2)),
                a[aa + 4] >> 3
            ];
            aa += 5;
            for (let j = 0; j < 8; j++) {
                r[8 * i + j] = int16((byte(t[j] & 31) * uint32(KyberService.paramsQ) + 16) >> 5);
            }
        }
        return r;
    }
}
