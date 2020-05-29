/*
 * Copyright 2020 William Swartzendruber
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a
 * copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package org.cryptokt.algo

import org.cryptokt.copyIntoLe
import org.cryptokt.leIntAt
import org.cryptokt.rl

/**
 * The second in the MD series by Ronald Rivest. It has been considered broken since 1995.
 *
 * @constructor Initializes a new MD4 instance with a block size of 512 bits and a digest size
 *     of 128 bits.
 */
public class Md4Hash : Hash(512, 128) {

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

        r[0] = r1(r[0], r[1], r[2], r[3], w[0], 3)
        r[3] = r1(r[3], r[0], r[1], r[2], w[1], 7)
        r[2] = r1(r[2], r[3], r[0], r[1], w[2], 11)
        r[1] = r1(r[1], r[2], r[3], r[0], w[3], 19)
        r[0] = r1(r[0], r[1], r[2], r[3], w[4], 3)
        r[3] = r1(r[3], r[0], r[1], r[2], w[5], 7)
        r[2] = r1(r[2], r[3], r[0], r[1], w[6], 11)
        r[1] = r1(r[1], r[2], r[3], r[0], w[7], 19)
        r[0] = r1(r[0], r[1], r[2], r[3], w[8], 3)
        r[3] = r1(r[3], r[0], r[1], r[2], w[9], 7)
        r[2] = r1(r[2], r[3], r[0], r[1], w[10], 11)
        r[1] = r1(r[1], r[2], r[3], r[0], w[11], 19)
        r[0] = r1(r[0], r[1], r[2], r[3], w[12], 3)
        r[3] = r1(r[3], r[0], r[1], r[2], w[13], 7)
        r[2] = r1(r[2], r[3], r[0], r[1], w[14], 11)
        r[1] = r1(r[1], r[2], r[3], r[0], w[15], 19)

        //
        // ROUND 2
        //

        r[0] = r2(r[0], r[1], r[2], r[3], w[0], 3)
        r[3] = r2(r[3], r[0], r[1], r[2], w[4], 5)
        r[2] = r2(r[2], r[3], r[0], r[1], w[8], 9)
        r[1] = r2(r[1], r[2], r[3], r[0], w[12], 13)
        r[0] = r2(r[0], r[1], r[2], r[3], w[1], 3)
        r[3] = r2(r[3], r[0], r[1], r[2], w[5], 5)
        r[2] = r2(r[2], r[3], r[0], r[1], w[9], 9)
        r[1] = r2(r[1], r[2], r[3], r[0], w[13], 13)
        r[0] = r2(r[0], r[1], r[2], r[3], w[2], 3)
        r[3] = r2(r[3], r[0], r[1], r[2], w[6], 5)
        r[2] = r2(r[2], r[3], r[0], r[1], w[10], 9)
        r[1] = r2(r[1], r[2], r[3], r[0], w[14], 13)
        r[0] = r2(r[0], r[1], r[2], r[3], w[3], 3)
        r[3] = r2(r[3], r[0], r[1], r[2], w[7], 5)
        r[2] = r2(r[2], r[3], r[0], r[1], w[11], 9)
        r[1] = r2(r[1], r[2], r[3], r[0], w[15], 13)

        //
        // ROUND 3
        //

        r[0] = r3(r[0], r[1], r[2], r[3], w[0], 3)
        r[3] = r3(r[3], r[0], r[1], r[2], w[8], 9)
        r[2] = r3(r[2], r[3], r[0], r[1], w[4], 11)
        r[1] = r3(r[1], r[2], r[3], r[0], w[12], 15)
        r[0] = r3(r[0], r[1], r[2], r[3], w[2], 3)
        r[3] = r3(r[3], r[0], r[1], r[2], w[10], 9)
        r[2] = r3(r[2], r[3], r[0], r[1], w[6], 11)
        r[1] = r3(r[1], r[2], r[3], r[0], w[14], 15)
        r[0] = r3(r[0], r[1], r[2], r[3], w[1], 3)
        r[3] = r3(r[3], r[0], r[1], r[2], w[9], 9)
        r[2] = r3(r[2], r[3], r[0], r[1], w[5], 11)
        r[1] = r3(r[1], r[2], r[3], r[0], w[13], 15)
        r[0] = r3(r[0], r[1], r[2], r[3], w[3], 3)
        r[3] = r3(r[3], r[0], r[1], r[2], w[11], 9)
        r[2] = r3(r[2], r[3], r[0], r[1], w[7], 11)
        r[1] = r3(r[1], r[2], r[3], r[0], w[15], 15)

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

        private fun r1(p1: Int, p2: Int, p3: Int, p4: Int, p5: Int, p6: Int) =
            (p1 + ((p2 and p3) or (p2.inv() and p4)) + p5) rl p6

        private fun r2(p1: Int, p2: Int, p3: Int, p4: Int, p5: Int, p6: Int) =
            (p1 + ((p2 and p3) or (p2 and p4) or (p3 and p4)) + p5 + 1518500249) rl p6

        private fun r3(p1: Int, p2: Int, p3: Int, p4: Int, p5: Int, p6: Int) =
            (p1 + (p2 xor p3 xor p4) + p5 + 1859775393) rl p6
    }
}
