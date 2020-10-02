/*
 * Copyright 2020 William Swartzendruber
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

/**
 * The first formally published version of the U.S. Secure Hash Algorithm. It has had
 * diminishing levels of security since 2010 and was fully broken in 2019.
 *
 * @constructor Initializes a new SHA1 instance with a block size of 512 bits and a digest size
 *     of 160 bits.
 */
public class Sha1DigestAlgorithm : DigestAlgorithm(512, 160) {

    private var ms = 0L
    private val r = cr.copyInto(IntArray(5))
    private val w = cw.copyInto(IntArray(80))

    protected override fun transformBlock(block: ByteArray): Unit {

        for (t in 0 until 16)
            w[t] = block.beIntAt(4 * t)

        for (t in 16 until 80)
            w[t] = (w[t - 3] xor w[t - 8] xor w[t - 14] xor w[t - 16]) rl 1

        var t1: Int
        var a = r[0]
        var b = r[1]
        var c = r[2]
        var d = r[3]
        var e = r[4]

        for (t in 0 until 20) {
            t1 = (a rl 5) + ((b and c) or (b.inv() and d)) + e + w[t] + K1
            e = d
            d = c
            c = b rl 30
            b = a
            a = t1
        }

        for (t in 20 until 40) {
            t1 = (a rl 5) + (b xor c xor d) + e + w[t] + K2
            e = d
            d = c
            c = b rl 30
            b = a
            a = t1
        }

        for (t in 40 until 60) {
            t1 = (a rl 5) + ((b and c) or (b and d) or (c and d)) + e + w[t] + K3
            e = d
            d = c
            c = b rl 30
            b = a
            a = t1
        }

        for (t in 60 until 80) {
            t1 = (a rl 5) + (b xor c xor d) + e + w[t] + K4
            e = d
            d = c
            c = b rl 30
            b = a
            a = t1
        }

        r[0] += a
        r[1] += b
        r[2] += c
        r[3] += d
        r[4] += e

        ms += 512L
    }

    protected override fun transformFinal(
        output: ByteArray,
        offset: Int,
        remaining: ByteArray,
        remainingSize: Int,
    ): Unit {

        val lms = ms + remainingSize.toLong() * 8L

        if (remainingSize > 55) {
            padding.copyInto(remaining, remainingSize, 0, 64 - remainingSize)
            transformBlock(remaining)
            padding.copyInto(remaining, 0, 8, 64)
        } else {
            padding.copyInto(remaining, remainingSize, 0, 56 - remainingSize)
        }

        lms.copyIntoBe(remaining, 56)

        transformBlock(remaining)

        for (i in 0 until 5)
            r[i].copyIntoBe(output, 4 * i)
    }

    protected override fun resetState(): Unit {
        ms = 0L
        cr.copyInto(r)
        cw.copyInto(w)
    }

    private companion object {

        private const val K1 = 1518500249
        private const val K2 = 1859775393
        private const val K3 = -1894007588
        private const val K4 = -899497514

        private val cr = intArrayOf(1732584193, -271733879, -1732584194, 271733878, -1009589776)
        private val cw = IntArray(80)
        private val padding = byteArrayOf(
            -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0
        )
    }
}
