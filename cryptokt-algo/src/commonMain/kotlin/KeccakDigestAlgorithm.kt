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
 *
 * This is essentially a Kotlin port of the public domain C++ KeccakTools available at
 *
 *     https://github.com/KeccakTeam/KeccakTools
 *
 * This implementation seeks to be correct only inasmuch as that one is.
 */

package org.cryptokt.algo

import kotlin.experimental.or
import kotlin.experimental.xor

/**
 * The Keccak[c] function, implemented here as an extendable [DigestAlgorithm] class. This
 * serves as the basis for the SHA-3 suite of hash algorithms and also the SHAKE128 and SHAKE256
 * extendable output functions. Those classes should be used directly where possible.
 */
public class KeccakDigestAlgorithm(
    capacity: KeccakCapacity,
    digestSize: Int,
) : DigestAlgorithm(capacity.rate, digestSize) {

    private val a = LongArray(25)
    private val at = LongArray(25)
    private val t1 = LongArray(5)
    private val t2 = LongArray(5)
    private val p = ByteArray(200)
    private val s = ByteArray(200)
    private val c = capacity.capacity
    private val r = capacity.rate

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
    }

    protected override fun resetState(): Unit {
        cl.copyInto(a)
        cl.copyInto(at)
        cl.copyInto(t1, endIndex = 5)
        cl.copyInto(t2, endIndex = 5)
        cb.copyInto(p)
        cb.copyInto(s)
    }

    private fun sponge() {
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
        for (x in 0 until 5) {
            t1[x] = a[index(x, 0)]
            for (y in 1 until 5)
                t1[x] = t1[x] xor a[index(x, y)]
        }
        for (x in 0 until 5)
            t2[x] = (t1[index(x + 1)] rol 1) xor t1[index(x - 1)]
        for (x in 0 until 5) {
            for (y in 0 until 5)
                a[index(x, y)] = a[index(x, y)] xor t2[x]
        }
    }

    private fun rho() {
        for (x in 0 until 5) {
            for (y in 0 until 5)
                a[index(x, y)] = a[index(x, y)] rl rhoOffsets[index(x, y)]
        }
    }

    private fun pi() {
        a.copyInto(at)
        for (x in 0 until 5) {
            for (y in 0 until 5) {
                val xt = (0 * x + 1 * y) % 5
                val yt = (2 * x + 3 * y) % 5
                a[index(xt, yt)] = at[index(x, y)]
            }
        }
    }

    private fun chi() {
        for (y in 0 until 5) {
            for (x in 0 until 5)
                t1[x] = a[index(x, y)] xor (a[index(x + 1, y)].inv() and a[index(x + 2, y)])
            for (x in 0 until 5)
                a[index(x, y)] = t1[x]
        }
    }

    private fun iota(roundIndex: Int) {
        a[0] = a[0] xor roundConstants[((roundIndex % 255) + 255) % 255]
    }

    private companion object {

        private const val B = 1600
        private const val W = 64
        private const val L = 6

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

        private fun index(x: Int): Int {

            var x2 = x

            x2 %= 5
            if (x2 < 0) x2 += 5

            return x2
        }

        private fun index(x: Int, y: Int): Int {

            var x2 = x
            var y2 = y

            x2 %= 5
            if (x2 < 0) x2 += 5
            y2 %= 5
            if (y2 < 0) y2 += 5

            return(x2 + (5*y2))
        }

        private infix fun Long.rol(offset: Int): Long {

            var offset2 = offset
            var this2 = this

            offset2 %= 64
            if (offset2 < 0) offset2 += 64

            if (offset2 != 0) {
                this2 = (this2 shl offset2) xor (this2 ushr (64 - offset2))
            }

            return this2
        }
    }
}
