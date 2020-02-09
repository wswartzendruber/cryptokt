/*
 * Copyright 2020 William Swartzendruber
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.cryptokt.algo

import org.cryptokt.copyIntoLe
import org.cryptokt.leIntAt
import org.cryptokt.rl

/**
 * The third in the MD series by Ronald Rivest. It has been considered broken since 2013.
 *
 * @constructor Initializes a new MD5 instance with a block size of 512 bits and a digest size
 *     of 128 bits.
 */
public class Md5Hash : Hash(512, 128) {

    private var ms = 0L
    private val r = cr.copyInto(IntArray(4))
    private val w = cw.copyInto(IntArray(16))

    protected override fun transformBlock(block: ByteArray): Unit {

        //
        // READ BLOCK
        //

        for (i in 0..15)
            w[i] = block.leIntAt(4 * i)

        val aa = r[0]
        val bb = r[1]
        val cc = r[2]
        val dd = r[3]

        //
        // ROUND 1
        //

        r[0] = r1(r[0], r[1], r[2], r[3], w[0], -680876936, 7)
        r[3] = r1(r[3], r[0], r[1], r[2], w[1], -389564586, 12)
        r[2] = r1(r[2], r[3], r[0], r[1], w[2], 606105819, 17)
        r[1] = r1(r[1], r[2], r[3], r[0], w[3], -1044525330, 22)
        r[0] = r1(r[0], r[1], r[2], r[3], w[4], -176418897, 7)
        r[3] = r1(r[3], r[0], r[1], r[2], w[5], 1200080426, 12)
        r[2] = r1(r[2], r[3], r[0], r[1], w[6], -1473231341, 17)
        r[1] = r1(r[1], r[2], r[3], r[0], w[7], -45705983, 22)
        r[0] = r1(r[0], r[1], r[2], r[3], w[8], 1770035416, 7)
        r[3] = r1(r[3], r[0], r[1], r[2], w[9], -1958414417, 12)
        r[2] = r1(r[2], r[3], r[0], r[1], w[10], -42063, 17)
        r[1] = r1(r[1], r[2], r[3], r[0], w[11], -1990404162, 22)
        r[0] = r1(r[0], r[1], r[2], r[3], w[12], 1804603682, 7)
        r[3] = r1(r[3], r[0], r[1], r[2], w[13], -40341101, 12)
        r[2] = r1(r[2], r[3], r[0], r[1], w[14], -1502002290, 17)
        r[1] = r1(r[1], r[2], r[3], r[0], w[15], 1236535329, 22)

        //
        // ROUND 2
        //

        r[0] = r2(r[0], r[1], r[2], r[3], w[1], -165796510, 5)
        r[3] = r2(r[3], r[0], r[1], r[2], w[6], -1069501632, 9)
        r[2] = r2(r[2], r[3], r[0], r[1], w[11], 643717713, 14)
        r[1] = r2(r[1], r[2], r[3], r[0], w[0], -373897302, 20)
        r[0] = r2(r[0], r[1], r[2], r[3], w[5], -701558691, 5)
        r[3] = r2(r[3], r[0], r[1], r[2], w[10], 38016083, 9)
        r[2] = r2(r[2], r[3], r[0], r[1], w[15], -660478335, 14)
        r[1] = r2(r[1], r[2], r[3], r[0], w[4], -405537848, 20)
        r[0] = r2(r[0], r[1], r[2], r[3], w[9], 568446438, 5)
        r[3] = r2(r[3], r[0], r[1], r[2], w[14], -1019803690, 9)
        r[2] = r2(r[2], r[3], r[0], r[1], w[3], -187363961, 14)
        r[1] = r2(r[1], r[2], r[3], r[0], w[8], 1163531501, 20)
        r[0] = r2(r[0], r[1], r[2], r[3], w[13], -1444681467, 5)
        r[3] = r2(r[3], r[0], r[1], r[2], w[2], -51403784, 9)
        r[2] = r2(r[2], r[3], r[0], r[1], w[7], 1735328473, 14)
        r[1] = r2(r[1], r[2], r[3], r[0], w[12], -1926607734, 20)

        //
        // ROUND 3
        //

        r[0] = r3(r[0], r[1], r[2], r[3], w[5], -378558, 4)
        r[3] = r3(r[3], r[0], r[1], r[2], w[8], -2022574463, 11)
        r[2] = r3(r[2], r[3], r[0], r[1], w[11], 1839030562, 16)
        r[1] = r3(r[1], r[2], r[3], r[0], w[14], -35309556, 23)
        r[0] = r3(r[0], r[1], r[2], r[3], w[1], -1530992060, 4)
        r[3] = r3(r[3], r[0], r[1], r[2], w[4], 1272893353, 11)
        r[2] = r3(r[2], r[3], r[0], r[1], w[7], -155497632, 16)
        r[1] = r3(r[1], r[2], r[3], r[0], w[10], -1094730640, 23)
        r[0] = r3(r[0], r[1], r[2], r[3], w[13], 681279174, 4)
        r[3] = r3(r[3], r[0], r[1], r[2], w[0], -358537222, 11)
        r[2] = r3(r[2], r[3], r[0], r[1], w[3], -722521979, 16)
        r[1] = r3(r[1], r[2], r[3], r[0], w[6], 76029189, 23)
        r[0] = r3(r[0], r[1], r[2], r[3], w[9], -640364487, 4)
        r[3] = r3(r[3], r[0], r[1], r[2], w[12], -421815835, 11)
        r[2] = r3(r[2], r[3], r[0], r[1], w[15], 530742520, 16)
        r[1] = r3(r[1], r[2], r[3], r[0], w[2], -995338651, 23)

        //
        // ROUND 4
        //

        r[0] = r4(r[0], r[1], r[2], r[3], w[0], -198630844, 6)
        r[3] = r4(r[3], r[0], r[1], r[2], w[7], 1126891415, 10)
        r[2] = r4(r[2], r[3], r[0], r[1], w[14], -1416354905, 15)
        r[1] = r4(r[1], r[2], r[3], r[0], w[5], -57434055, 21)
        r[0] = r4(r[0], r[1], r[2], r[3], w[12], 1700485571, 6)
        r[3] = r4(r[3], r[0], r[1], r[2], w[3], -1894986606, 10)
        r[2] = r4(r[2], r[3], r[0], r[1], w[10], -1051523, 15)
        r[1] = r4(r[1], r[2], r[3], r[0], w[1], -2054922799, 21)
        r[0] = r4(r[0], r[1], r[2], r[3], w[8], 1873313359, 6)
        r[3] = r4(r[3], r[0], r[1], r[2], w[15], -30611744, 10)
        r[2] = r4(r[2], r[3], r[0], r[1], w[6], -1560198380, 15)
        r[1] = r4(r[1], r[2], r[3], r[0], w[13], 1309151649, 21)
        r[0] = r4(r[0], r[1], r[2], r[3], w[4], -145523070, 6)
        r[3] = r4(r[3], r[0], r[1], r[2], w[11], -1120210379, 10)
        r[2] = r4(r[2], r[3], r[0], r[1], w[2], 718787259, 15)
        r[1] = r4(r[1], r[2], r[3], r[0], w[9], -343485551, 21)

        r[0] += aa
        r[1] += bb
        r[2] += cc
        r[3] += dd

        ms += 512L
    }

    protected override fun transformFinal(
        output: ByteArray,
        offset: Int,
        remaining: ByteArray,
        remainingSize: Int
    ): Unit {

        val lms = ms + remainingSize.toLong() * 8L

        if (remainingSize > 55) {
            padding.copyInto(remaining, remainingSize, 0, 64 - remainingSize)
            transformBlock(remaining)
            padding.copyInto(remaining, 0, 8, 64)
        } else {
            padding.copyInto(remaining, remainingSize, 0, 56 - remainingSize)
        }

        lms.copyIntoLe(remaining, 56)

        transformBlock(remaining)

        for (i in 0..3)
            r[i].copyIntoLe(output, 4 * i)
    }

    protected override fun resetState(): Unit {
        ms = 0L
        cr.copyInto(r)
        cw.copyInto(w)
    }

    private companion object {

        private val cr = intArrayOf(1732584193, -271733879, -1732584194, 271733878)
        private val cw = IntArray(16)
        private val padding = byteArrayOf(
            -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0
        )

        private fun r1(a: Int, b: Int, c: Int, d: Int, x: Int, t: Int, s: Int) =
            b + ((a + ((b and c) or (b.inv() and d)) + x + t) rl s)

        private fun r2(a: Int, b: Int, c: Int, d: Int, x: Int, t: Int, s: Int) =
            b + ((a + ((b and d) or (c and d.inv())) + x + t) rl s)

        private fun r3(a: Int, b: Int, c: Int, d: Int, x: Int, t: Int, s: Int) =
            b + ((a + (b xor c xor d) + x + t) rl s)

        private fun r4(a: Int, b: Int, c: Int, d: Int, x: Int, t: Int, s: Int) =
            b + ((a + (c xor (b or d.inv())) + x + t) rl s)
    }
}
