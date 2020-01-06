/*
 * Copyright 2019 William Swartzendruber
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
import org.cryptokt.forEachSegment
import org.cryptokt.leIntAt
import org.cryptokt.rl

/**
 * The second in the MD series by Ronald Rivest. It has a digest size of 128 bits. It has been
 * considered broken since 1995.
 */
public class Md4Hash : Hash() {

    private var mo = 0
    private var ms = 0L
    private val mb = ByteArray(64)
    private val r = IntArray(4)
    private val w = IntArray(16)

    init {
        clear()
    }

    public override fun input(buffer: ByteArray, offset: Int, length: Int) {
        mo = forEachSegment(
            mb, mo,
            buffer, offset, length,
            {
                transformBlock()
            }
        )
        ms += (length * 8).toLong()
    }

    public override fun digest(output: ByteArray, offset: Int): ByteArray {

        //
        // APPEND PADDING
        //

        if (mo > 55) {
            padding.copyInto(mb, mo, 0, 64 - mo)
            transformBlock()
            padding.copyInto(mb, 0, 8, 64)
        } else {
            padding.copyInto(mb, mo, 0, 56 - mo)
        }

        //
        // APPEND LENGTH
        //

        ms.copyIntoLe(mb, 56)

        //
        // TRANSFORM PADDING + LENGTH
        //

        transformBlock()

        //
        // SET OUTPUT
        //

        for (i in 0..3)
            r[i].copyIntoLe(output, 4 * i)

        clear()

        return output
    }

    private fun clear() {
        mo = 0
        ms = 0L
        cmb.copyInto(mb)
        cr.copyInto(r)
        cw.copyInto(w)
    }

    private fun transformBlock() {

        //
        // READ BLOCK
        //

        for (i in 0..15)
            w[i] = mb.leIntAt(4 * i)

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
    }

    public override val length: Int = 16

    public override val size: Int = 128

    private companion object {

        private val cmb = ByteArray(64)
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
