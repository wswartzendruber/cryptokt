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

import org.cryptokt.forEachSegment
import org.cryptokt.rl

/**
 * The first formally published version of the U.S. Secure Hash Algorithm. It has a digest size
 * of 160 bits. It has had progressively diminished levels of security beginning in 2010 and was
 * fully broken in 2019.
 */
public class Sha1HashAlgorithm : HashAlgorithm() {

    private var mo = 0
    private var ms = 0L
    private val mb = ByteArray(64)
    private val r = IntArray(5)
    private val w = IntArray(80)

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

        mb[56] = ms.ushr(56).toByte()
        mb[57] = ms.ushr(48).toByte()
        mb[58] = ms.ushr(40).toByte()
        mb[59] = ms.ushr(32).toByte()
        mb[60] = ms.ushr(24).toByte()
        mb[61] = ms.ushr(16).toByte()
        mb[62] = ms.ushr(8).toByte()
        mb[63] = ms.toByte()

        //
        // TRANSFORM PADDING + LENGTH
        //

        transformBlock()

        //
        // SET OUTPUT
        //

        output[0 + offset] = r[0].ushr(24).toByte()
        output[1 + offset] = r[0].ushr(16).toByte()
        output[2 + offset] = r[0].ushr(8).toByte()
        output[3 + offset] = r[0].toByte()
        output[4 + offset] = r[1].ushr(24).toByte()
        output[5 + offset] = r[1].ushr(16).toByte()
        output[6 + offset] = r[1].ushr(8).toByte()
        output[7 + offset] = r[1].toByte()
        output[8 + offset] = r[2].ushr(24).toByte()
        output[9 + offset] = r[2].ushr(16).toByte()
        output[10 + offset] = r[2].ushr(8).toByte()
        output[11 + offset] = r[2].toByte()
        output[12 + offset] = r[3].ushr(24).toByte()
        output[13 + offset] = r[3].ushr(16).toByte()
        output[14 + offset] = r[3].ushr(8).toByte()
        output[15 + offset] = r[3].toByte()
        output[16 + offset] = r[4].ushr(24).toByte()
        output[17 + offset] = r[4].ushr(16).toByte()
        output[18 + offset] = r[4].ushr(8).toByte()
        output[19 + offset] = r[4].toByte()

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

        var t: Int

        for (i in 0..15) {
            t = 4 * i
            w[i] = (mb[t + 3].toInt() and 255) or
                (mb[t + 2].toInt() and 255 shl 8) or
                (mb[t + 1].toInt() and 255 shl 16) or
                (mb[t].toInt() shl 24)
        }

        for (i in 16..79)
            w[i] = (w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16]) rl 1

        var ra = r[0]
        var rb = r[1]
        var rc = r[2]
        var rd = r[3]
        var re = r[4]

        for (i in 0..19) {
            t = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w[i] + K1
            re = rd
            rd = rc
            rc = rb rl 30
            rb = ra
            ra = t
        }

        for (i in 20..39) {
            t = (ra rl 5) + (rb xor rc xor rd) + re + w[i] + K2
            re = rd
            rd = rc
            rc = rb rl 30
            rb = ra
            ra = t
        }

        for (i in 40..59) {
            t = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w[i] + K3
            re = rd
            rd = rc
            rc = rb rl 30
            rb = ra
            ra = t
        }

        for (i in 60..79) {
            t = (ra rl 5) + (rb xor rc xor rd) + re + w[i] + K4
            re = rd
            rd = rc
            rc = rb rl 30
            rb = ra
            ra = t
        }

        r[0] += ra
        r[1] += rb
        r[2] += rc
        r[3] += rd
        r[4] += re
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
