/*
 * Copyright 2021 William Swartzendruber
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */

package org.cryptokt.algo

import kotlin.experimental.or
import kotlin.experimental.xor
import kotlin.math.min

/**
 * The Keccak[c] function, implemented here as an abstract [DigestAlgorithm] class. This serves
 * as the basis for the SHA-3 suite of hash algorithms and also the SHAKE128 and SHAKE256
 * extendable output functions. The block and digest sizes vary.
 *
 * @param[capacity] The capacity in bytes of the Keccak sponge function. See FIPS-202 Section 4
 *     for more information.
 * @param[digestSize] The size in bytes of the digest.
 * @param[paddingSingle] The byte value to use should a single padding byte be needed. See
 *     FIPS-202 Appendix B.2 for more information.
 * @param[paddingStart] The starting byte value to use should multiple padding bytes be needed.
 *     See FIPS-202 Appendix B.2 for more information.
 * @param[paddingEnd] The ending byte value to use should multiple padding bytes be needed. See
 *     FIPS-202 Appendix B.2 for more information.
 */
public abstract class KeccakDigestAlgorithm(
    capacity: Int,
    digestSize: Int,
    private val paddingSingle: Byte,
    private val paddingStart: Byte,
    private val paddingEnd: Byte,
) : DigestAlgorithm(200 - capacity, digestSize) {

    private val a = LongArray(25)
    private val at = LongArray(25)
    private val t1 = LongArray(5)
    private val t2 = LongArray(5)
    private val p = ByteArray(200)
    private val s = ByteArray(200)

    protected override fun transformBlock(block: ByteArray): Unit {
        block.copyInto(p)
        for (i in 0 until 200)
            s[i] = s[i] xor p[i]
        permutate()
    }

    protected override fun transformFinal(
        output: ByteArray,
        offset: Int,
        remaining: ByteArray,
        remainingSize: Int,
    ): Unit {

        val left = blockSize - remainingSize

        when {
            left == 1 -> {
                remaining[blockSize - 1] = paddingSingle
            }
            left >= 2 -> {
                remaining[remainingSize] = paddingStart
                for (i in (remainingSize + 1) until (blockSize - 1))
                    remaining[i] = 0
                remaining[blockSize - 1] = paddingEnd
            }
            else -> {
                throw IllegalStateException("Remaining input block is in an invalid state.")
            }
        }

        transformBlock(remaining)

        var index = 0
        var increment: Int

        while (index < digestSize) {
            increment = min(blockSize, digestSize - index)
            s.copyInto(output, index + offset, 0, increment)
            index += increment
            if (index < digestSize)
                permutate()
        }
    }

    protected override fun resetState(): Unit {
        cl.copyInto(a)
        cl.copyInto(at)
        cl.copyInto(t1, endIndex = 5)
        cl.copyInto(t2, endIndex = 5)
        cb.copyInto(p)
        cb.copyInto(s)
    }

    private fun permutate() {
        bytesToLanes()
        for (r in 0 until 24) {
            theta()
            rho()
            pi()
            chi()
            iota(r)
        }
        lanesToBytes()
    }

    private fun bytesToLanes() {
        for (i in 0 until 25) {
            a[i] = 0
            for (j in 0 until 8)
                a[i] = a[i] or (s[i * 8 + j].toLong() and 255 shl (8 * j))
        }
    }

    private fun lanesToBytes() {
        for (i in 0 until 25) {
            for (j in 0 until 8)
                s[i * 8 + j] = ((a[i] ushr (8 * j)) and 255).toByte()
        }
    }

    private fun theta() {
        t1[0] = a[0]
        t1[0] = t1[0] xor a[5]
        t1[0] = t1[0] xor a[10]
        t1[0] = t1[0] xor a[15]
        t1[0] = t1[0] xor a[20]
        t1[1] = a[1]
        t1[1] = t1[1] xor a[6]
        t1[1] = t1[1] xor a[11]
        t1[1] = t1[1] xor a[16]
        t1[1] = t1[1] xor a[21]
        t1[2] = a[2]
        t1[2] = t1[2] xor a[7]
        t1[2] = t1[2] xor a[12]
        t1[2] = t1[2] xor a[17]
        t1[2] = t1[2] xor a[22]
        t1[3] = a[3]
        t1[3] = t1[3] xor a[8]
        t1[3] = t1[3] xor a[13]
        t1[3] = t1[3] xor a[18]
        t1[3] = t1[3] xor a[23]
        t1[4] = a[4]
        t1[4] = t1[4] xor a[9]
        t1[4] = t1[4] xor a[14]
        t1[4] = t1[4] xor a[19]
        t1[4] = t1[4] xor a[24]
        t2[0] = (t1[1] rl 1) xor t1[4]
        t2[1] = (t1[2] rl 1) xor t1[0]
        t2[2] = (t1[3] rl 1) xor t1[1]
        t2[3] = (t1[4] rl 1) xor t1[2]
        t2[4] = (t1[0] rl 1) xor t1[3]
        a[0] = a[0] xor t2[0]
        a[5] = a[5] xor t2[0]
        a[10] = a[10] xor t2[0]
        a[15] = a[15] xor t2[0]
        a[20] = a[20] xor t2[0]
        a[1] = a[1] xor t2[1]
        a[6] = a[6] xor t2[1]
        a[11] = a[11] xor t2[1]
        a[16] = a[16] xor t2[1]
        a[21] = a[21] xor t2[1]
        a[2] = a[2] xor t2[2]
        a[7] = a[7] xor t2[2]
        a[12] = a[12] xor t2[2]
        a[17] = a[17] xor t2[2]
        a[22] = a[22] xor t2[2]
        a[3] = a[3] xor t2[3]
        a[8] = a[8] xor t2[3]
        a[13] = a[13] xor t2[3]
        a[18] = a[18] xor t2[3]
        a[23] = a[23] xor t2[3]
        a[4] = a[4] xor t2[4]
        a[9] = a[9] xor t2[4]
        a[14] = a[14] xor t2[4]
        a[19] = a[19] xor t2[4]
        a[24] = a[24] xor t2[4]
    }

    private fun rho() {
        for (i in 0 until 25)
            a[i] = a[i] rl rhoOffsets[i]
    }

    private fun pi() {
        a.copyInto(at)
        a[0] = at[0]
        a[16] = at[5]
        a[7] = at[10]
        a[23] = at[15]
        a[14] = at[20]
        a[10] = at[1]
        a[1] = at[6]
        a[17] = at[11]
        a[8] = at[16]
        a[24] = at[21]
        a[20] = at[2]
        a[11] = at[7]
        a[2] = at[12]
        a[18] = at[17]
        a[9] = at[22]
        a[5] = at[3]
        a[21] = at[8]
        a[12] = at[13]
        a[3] = at[18]
        a[19] = at[23]
        a[15] = at[4]
        a[6] = at[9]
        a[22] = at[14]
        a[13] = at[19]
        a[4] = at[24]
    }

    private fun chi() {
        t1[0] = a[0] xor (a[1].inv() and a[2])
        t1[1] = a[1] xor (a[2].inv() and a[3])
        t1[2] = a[2] xor (a[3].inv() and a[4])
        t1[3] = a[3] xor (a[4].inv() and a[0])
        t1[4] = a[4] xor (a[0].inv() and a[1])
        a[0] = t1[0]
        a[1] = t1[1]
        a[2] = t1[2]
        a[3] = t1[3]
        a[4] = t1[4]
        t1[0] = a[5] xor (a[6].inv() and a[7])
        t1[1] = a[6] xor (a[7].inv() and a[8])
        t1[2] = a[7] xor (a[8].inv() and a[9])
        t1[3] = a[8] xor (a[9].inv() and a[5])
        t1[4] = a[9] xor (a[5].inv() and a[6])
        a[5] = t1[0]
        a[6] = t1[1]
        a[7] = t1[2]
        a[8] = t1[3]
        a[9] = t1[4]
        t1[0] = a[10] xor (a[11].inv() and a[12])
        t1[1] = a[11] xor (a[12].inv() and a[13])
        t1[2] = a[12] xor (a[13].inv() and a[14])
        t1[3] = a[13] xor (a[14].inv() and a[10])
        t1[4] = a[14] xor (a[10].inv() and a[11])
        a[10] = t1[0]
        a[11] = t1[1]
        a[12] = t1[2]
        a[13] = t1[3]
        a[14] = t1[4]
        t1[0] = a[15] xor (a[16].inv() and a[17])
        t1[1] = a[16] xor (a[17].inv() and a[18])
        t1[2] = a[17] xor (a[18].inv() and a[19])
        t1[3] = a[18] xor (a[19].inv() and a[15])
        t1[4] = a[19] xor (a[15].inv() and a[16])
        a[15] = t1[0]
        a[16] = t1[1]
        a[17] = t1[2]
        a[18] = t1[3]
        a[19] = t1[4]
        t1[0] = a[20] xor (a[21].inv() and a[22])
        t1[1] = a[21] xor (a[22].inv() and a[23])
        t1[2] = a[22] xor (a[23].inv() and a[24])
        t1[3] = a[23] xor (a[24].inv() and a[20])
        t1[4] = a[24] xor (a[20].inv() and a[21])
        a[20] = t1[0]
        a[21] = t1[1]
        a[22] = t1[2]
        a[23] = t1[3]
        a[24] = t1[4]
    }

    private fun iota(roundIndex: Int) {
        a[0] = a[0] xor roundConstants[((roundIndex % 255) + 255) % 255]
    }

    private companion object {

        private val cb = ByteArray(200)
        private val cl = LongArray(25)
        private val rhoOffsets = intArrayOf(
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
            25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
        )
        private val roundConstants = longArrayOf(
            1, 32898, -9223372036854742902, -9223372034707259392, 32907, 2147483649,
            -9223372034707259263, -9223372036854743031, 138, 136, 2147516425, 2147483658,
            2147516555, -9223372036854775669, -9223372036854742903, -9223372036854743037,
            -9223372036854743038, -9223372036854775680, 32778, -9223372034707292150,
            -9223372034707259263, -9223372036854742912, 2147483649, -9223372034707259384,
            -9223372034707259262, -9223372034707259382, -9223372036854775805,
            -9223372034707292151, -9223372036854742910, 32777, -9223372036854775680, 32899,
            -9223372036854775679, 1, 32779, -9223372034707259391, 128, -9223372036854743040,
            -9223372034707259391, 9, -9223372034707259253, 129, -9223372036854775678,
            2147483787, -9223372034707259383, -9223372034707292160, 2147483776, 2147516419,
            -9223372034707259262, -9223372034707259261, -9223372034707292024, 32905, 32777,
            -9223372036854775799, 2147516424, 2147516417, -9223372036854775670,
            -9223372036854775797, 137, 2147483650, -9223372036854743029, 2147516427, 32907,
            2147483784, -9223372036854743030, 2147483785, -9223372036854775807,
            -9223372036854742904, -9223372036854775679, 136, 2147516544, 129,
            -9223372036854775797, 0, 137, 2147483787, -9223372034707259264,
            -9223372036854775669, -9223372036854743040, -9223372034707259256, 2147483778, 11,
            -9223372036854775798, 32898, -9223372036854743037, -9223372036854742901,
            -9223372034707292149, -9223372034707292022, 2147483777, 2147483777, 2147483656, 131,
            -9223372034707259389, 2147516552, -9223372034707292024, 32768, 2147516546,
            2147516553, -9223372034707259261, -9223372034707292159, 2147516418,
            -9223372034707292023, 130, -9223372034707292152, -9223372036854775671,
            -9223372034707292152, Long.MIN_VALUE, -9223372036854775677, 2147516544, 8,
            -9223372034707292032, -9223372034707259264, -9223372036854775806,
            -9223372034707259253, 8, -9223372034707292151, -9223372036854743029, 2147516546,
            2147516416, -9223372036854743032, 32897, -9223372034707259255, 2147516553,
            -9223372034707259382, -9223372036854775670, -9223372036854775678, 2147483650,
            -9223372036854742910, 32896, -9223372034707292149, -9223372034707292157, 10,
            -9223372036854743039, -9223372034707292029, -9223372036854742909, 139, 32778,
            -9223372034707292029, -9223372036854743030, 2147483648, -9223372034707292022,
            2147483656, 10, -9223372036854742904, -9223372036854775800, 2147483651,
            Long.MIN_VALUE, -9223372036854775798, 32779, -9223372034707259256, 2147483659,
            2147483776, 2147516554, -9223372036854743031, 3, 2147483651, -9223372036854775671,
            -9223372034707292031, -9223372034707292021, 2147516419, -9223372034707259381,
            -9223372036854743032, 32776, -9223372036854743038, -9223372036854775799, 2147516545,
            32906, 2147516426, 128, -9223372036854742903, -9223372036854742902,
            -9223372034707259255, 2147516416, -9223372036854742911, 2147516426, 9,
            -9223372034707259390, 2147483658, 2147516418, -9223372034707292160, 2147483657,
            32904, 2, 2147516424, 2147516552, -9223372034707292159, 2147516555,
            -9223372036854775806, -9223372034707259390, 2147483779, 32905, 32896,
            -9223372034707292030, -9223372036854775672, -9223372034707259254, 32906, 2147516547,
            2147483659, 2147483657, 32769, 2147483785, -9223372036854775672,
            -9223372034707259389, 2147516417, -9223372036854775805, -9223372034707292032,
            -9223372034707259383, -9223372034707292023, 11, -9223372036854775677, 2147516425,
            2147483779, 32768, 2147516427, 32770, 3, 2147483786, -9223372034707292158, 32769,
            2147483648, -9223372034707292157, 131, -9223372034707259254, 32771, 32776,
            -9223372036854742901, -9223372034707292030, -9223372036854775807,
            -9223372036854743039, -9223372034707292150, -9223372034707259384,
            -9223372034707259381, -9223372036854742911, 2147516547, 2147483778, 130,
            -9223372034707292031, -9223372034707292158, 32904, 139, 32899, -9223372036854775800,
            2147483786, -9223372034707292021, 2147516554, -9223372036854742912, 2147483784,
            -9223372036854742909, 2, 2147516545, 32771, 32897, -9223372034707259392, 32770, 138,
        )
        private val xyIndices = intArrayOf(
            5, 10, 15, 20, 6, 11, 16, 21, 7, 12, 17, 22, 8, 13, 18, 23, 9, 14, 19, 24,
        )
    }
}
