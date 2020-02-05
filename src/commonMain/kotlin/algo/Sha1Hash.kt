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

import org.cryptokt.beIntAt
import org.cryptokt.copyIntoBe
import org.cryptokt.forEachSegment
import org.cryptokt.rl

/**
 * The first formally published version of the U.S. Secure Hash Algorithm. It has a digest size
 * of 160 bits. It has had progressively diminished levels of security beginning in 2010 and was
 * fully broken in 2019.
 */
public class Sha1Hash : Hash() {

    private var mo = 0
    private var ms = 0L
    private val mb = ByteArray(64)
    private val r = IntArray(5)
    private val w = IntArray(80)

    init {
        reset()
    }

    public override fun input(buffer: ByteArray, offset: Int, length: Int): Unit {
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

        ms.copyIntoBe(mb, 56)

        //
        // TRANSFORM PADDING + LENGTH
        //

        transformBlock()

        //
        // SET OUTPUT
        //

        for (i in 0..4)
            r[i].copyIntoBe(output, 4 * i)

        reset()

        return output
    }

    public override fun reset(): Unit {
        mo = 0
        ms = 0L
        cmb.copyInto(mb)
        cr.copyInto(r)
        cw.copyInto(w)
    }

    private fun transformBlock() {

        for (t in 0..15)
            w[t] = mb.beIntAt(4 * t)

        for (t in 16..79)
            w[t] = (w[t - 3] xor w[t - 8] xor w[t - 14] xor w[t - 16]) rl 1

        var t1: Int
        var a = r[0]
        var b = r[1]
        var c = r[2]
        var d = r[3]
        var e = r[4]

        for (t in 0..19) {
            t1 = (a rl 5) + ((b and c) or (b.inv() and d)) + e + w[t] + K1
            e = d
            d = c
            c = b rl 30
            b = a
            a = t1
        }

        for (t in 20..39) {
            t1 = (a rl 5) + (b xor c xor d) + e + w[t] + K2
            e = d
            d = c
            c = b rl 30
            b = a
            a = t1
        }

        for (t in 40..59) {
            t1 = (a rl 5) + ((b and c) or (b and d) or (c and d)) + e + w[t] + K3
            e = d
            d = c
            c = b rl 30
            b = a
            a = t1
        }

        for (t in 60..79) {
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
    }

    public override val length: Int = 20

    public override val size: Int = 160

    private companion object {

        private const val K1 = 1518500249
        private const val K2 = 1859775393
        private const val K3 = -1894007588
        private const val K4 = -899497514

        private val cmb = ByteArray(64)
        private val cr = intArrayOf(1732584193, -271733879, -1732584194, 271733878, -1009589776)
        private val cw = IntArray(80)
        private val padding = byteArrayOf(
            -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0
        )
    }
}
