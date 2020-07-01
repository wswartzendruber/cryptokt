/*
 * Copyright 2020 William Swartzendruber
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a
 * copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package org.cryptokt.algo

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

        var aa = r[0]
        var bb = r[1]
        var cc = r[2]
        var dd = r[3]

        //
        // ROUND 1
        //

        aa = r1(aa, bb, cc, dd, w[0], -680876936, 7)
        dd = r1(dd, aa, bb, cc, w[1], -389564586, 12)
        cc = r1(cc, dd, aa, bb, w[2], 606105819, 17)
        bb = r1(bb, cc, dd, aa, w[3], -1044525330, 22)
        aa = r1(aa, bb, cc, dd, w[4], -176418897, 7)
        dd = r1(dd, aa, bb, cc, w[5], 1200080426, 12)
        cc = r1(cc, dd, aa, bb, w[6], -1473231341, 17)
        bb = r1(bb, cc, dd, aa, w[7], -45705983, 22)
        aa = r1(aa, bb, cc, dd, w[8], 1770035416, 7)
        dd = r1(dd, aa, bb, cc, w[9], -1958414417, 12)
        cc = r1(cc, dd, aa, bb, w[10], -42063, 17)
        bb = r1(bb, cc, dd, aa, w[11], -1990404162, 22)
        aa = r1(aa, bb, cc, dd, w[12], 1804603682, 7)
        dd = r1(dd, aa, bb, cc, w[13], -40341101, 12)
        cc = r1(cc, dd, aa, bb, w[14], -1502002290, 17)
        bb = r1(bb, cc, dd, aa, w[15], 1236535329, 22)

        //
        // ROUND 2
        //

        aa = r2(aa, bb, cc, dd, w[1], -165796510, 5)
        dd = r2(dd, aa, bb, cc, w[6], -1069501632, 9)
        cc = r2(cc, dd, aa, bb, w[11], 643717713, 14)
        bb = r2(bb, cc, dd, aa, w[0], -373897302, 20)
        aa = r2(aa, bb, cc, dd, w[5], -701558691, 5)
        dd = r2(dd, aa, bb, cc, w[10], 38016083, 9)
        cc = r2(cc, dd, aa, bb, w[15], -660478335, 14)
        bb = r2(bb, cc, dd, aa, w[4], -405537848, 20)
        aa = r2(aa, bb, cc, dd, w[9], 568446438, 5)
        dd = r2(dd, aa, bb, cc, w[14], -1019803690, 9)
        cc = r2(cc, dd, aa, bb, w[3], -187363961, 14)
        bb = r2(bb, cc, dd, aa, w[8], 1163531501, 20)
        aa = r2(aa, bb, cc, dd, w[13], -1444681467, 5)
        dd = r2(dd, aa, bb, cc, w[2], -51403784, 9)
        cc = r2(cc, dd, aa, bb, w[7], 1735328473, 14)
        bb = r2(bb, cc, dd, aa, w[12], -1926607734, 20)

        //
        // ROUND 3
        //

        aa = r3(aa, bb, cc, dd, w[5], -378558, 4)
        dd = r3(dd, aa, bb, cc, w[8], -2022574463, 11)
        cc = r3(cc, dd, aa, bb, w[11], 1839030562, 16)
        bb = r3(bb, cc, dd, aa, w[14], -35309556, 23)
        aa = r3(aa, bb, cc, dd, w[1], -1530992060, 4)
        dd = r3(dd, aa, bb, cc, w[4], 1272893353, 11)
        cc = r3(cc, dd, aa, bb, w[7], -155497632, 16)
        bb = r3(bb, cc, dd, aa, w[10], -1094730640, 23)
        aa = r3(aa, bb, cc, dd, w[13], 681279174, 4)
        dd = r3(dd, aa, bb, cc, w[0], -358537222, 11)
        cc = r3(cc, dd, aa, bb, w[3], -722521979, 16)
        bb = r3(bb, cc, dd, aa, w[6], 76029189, 23)
        aa = r3(aa, bb, cc, dd, w[9], -640364487, 4)
        dd = r3(dd, aa, bb, cc, w[12], -421815835, 11)
        cc = r3(cc, dd, aa, bb, w[15], 530742520, 16)
        bb = r3(bb, cc, dd, aa, w[2], -995338651, 23)

        //
        // ROUND 4
        //

        aa = r4(aa, bb, cc, dd, w[0], -198630844, 6)
        dd = r4(dd, aa, bb, cc, w[7], 1126891415, 10)
        cc = r4(cc, dd, aa, bb, w[14], -1416354905, 15)
        bb = r4(bb, cc, dd, aa, w[5], -57434055, 21)
        aa = r4(aa, bb, cc, dd, w[12], 1700485571, 6)
        dd = r4(dd, aa, bb, cc, w[3], -1894986606, 10)
        cc = r4(cc, dd, aa, bb, w[10], -1051523, 15)
        bb = r4(bb, cc, dd, aa, w[1], -2054922799, 21)
        aa = r4(aa, bb, cc, dd, w[8], 1873313359, 6)
        dd = r4(dd, aa, bb, cc, w[15], -30611744, 10)
        cc = r4(cc, dd, aa, bb, w[6], -1560198380, 15)
        bb = r4(bb, cc, dd, aa, w[13], 1309151649, 21)
        aa = r4(aa, bb, cc, dd, w[4], -145523070, 6)
        dd = r4(dd, aa, bb, cc, w[11], -1120210379, 10)
        cc = r4(cc, dd, aa, bb, w[2], 718787259, 15)
        bb = r4(bb, cc, dd, aa, w[9], -343485551, 21)

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
