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
    private val dw = ByteArray(80)
    private val imb = ByteArray(64)
    private val dmb = ByteArray(64)
    private val ir = IntArray(5)
    private val dr = IntArray(5)
    private val w = IntArray(80)

    init {
        reset()
    }

    public override fun input(buffer: ByteArray, offset: Int, length: Int) {
        mo = forEachSegment(
            imb, mo,
            buffer, offset, length,
            {
                transformBlock(ir, imb)
            }
        )
        ms += (length * 8).toLong()
    }

    public override fun digest(output: ByteArray, offset: Int): ByteArray {

        //
        // COPY STATE
        //

        imb.copyInto(dmb)
        ir.copyInto(dr)

        //
        // APPEND PADDING
        //

        if (mo > 55) {
            padding.copyInto(dmb, mo, 0, 64 - mo)
            transformBlock(dr, dmb)
            padding.copyInto(dmb, 0, 8, 64)
        } else {
            padding.copyInto(dmb, mo, 0, 56 - mo)
        }

        //
        // APPEND LENGTH
        //

        dmb[56] = ms.shr(56).toByte()
        dmb[57] = ms.shr(48).toByte()
        dmb[58] = ms.shr(40).toByte()
        dmb[59] = ms.shr(32).toByte()
        dmb[60] = ms.shr(24).toByte()
        dmb[61] = ms.shr(16).toByte()
        dmb[62] = ms.shr(8).toByte()
        dmb[63] = ms.toByte()

        //
        // TRANSFORM PADDING + LENGTH
        //

        transformBlock(dr, dmb)

        //
        // SET OUTPUT
        //

        output[0 + offset] = dr[0].shr(24).toByte()
        output[1 + offset] = dr[0].shr(16).toByte()
        output[2 + offset] = dr[0].shr(8).toByte()
        output[3 + offset] = dr[0].toByte()
        output[4 + offset] = dr[1].shr(24).toByte()
        output[5 + offset] = dr[1].shr(16).toByte()
        output[6 + offset] = dr[1].shr(8).toByte()
        output[7 + offset] = dr[1].toByte()
        output[8 + offset] = dr[2].shr(24).toByte()
        output[9 + offset] = dr[2].shr(16).toByte()
        output[10 + offset] = dr[2].shr(8).toByte()
        output[11 + offset] = dr[2].toByte()
        output[12 + offset] = dr[3].shr(24).toByte()
        output[13 + offset] = dr[3].shr(16).toByte()
        output[14 + offset] = dr[3].shr(8).toByte()
        output[15 + offset] = dr[3].toByte()
        output[16 + offset] = dr[4].shr(24).toByte()
        output[17 + offset] = dr[4].shr(16).toByte()
        output[18 + offset] = dr[4].shr(8).toByte()
        output[19 + offset] = dr[4].toByte()

        return output
    }

    public override fun reset() {
        mo = 0
        ms = 0L
        rw.copyInto(w)
        rmb.copyInto(imb)
        rmb.copyInto(dmb)
        rr.copyInto(ir)
        rr.copyInto(dr)
    }

    private fun transformBlock(r: IntArray, mb: ByteArray) {

        var t: Int

        for (i in 0..15) {
            t = 4 * i
            w[i] = mb[t + 3].toInt().and(255) or
            (mb[t + 2].toInt().and(255) shl 8) or
            (mb[t + 1].toInt().and(255) shl 16) or
            (mb[t].toInt() shl 24)
        }

        for (i in 16..79) {
            t = (w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16])
            w[i] = (t shl 1) or (t shr 31 and 1)
        }

        var ra = r[0]
        var rb = r[1]
        var rc = r[2]
        var rd = r[3]
        var re = r[4]

        for (i in 0..19) {
            t = ((ra shl 5) or (ra shr 27 and 31)) +
                ((rb and rc) or (rb.inv() and rd)) + re + w[i] + K1
            re = rd
            rd = rc
            rc = (rb shl 30) or (rb shr 2 and 1073741823)
            rb = ra
            ra = t
        }

        for (i in 20..39) {
            t = ((ra shl 5) or (ra shr 27 and 31)) + (rb xor rc xor rd) + re + w[i] + K2
            re = rd
            rd = rc
            rc = (rb shl 30) or (rb shr 2 and 1073741823)
            rb = ra
            ra = t
        }

        for (i in 40..59) {
            t = ((ra shl 5) or (ra shr 27 and 31)) +
                ((rb and rc) or (rb and rd) or (rc and rd)) + re + w[i] + K3
            re = rd
            rd = rc
            rc = (rb shl 30) or (rb shr 2 and 1073741823)
            rb = ra
            ra = t
        }

        for (i in 60..79) {
            t = ((ra shl 5) or (ra shr 27 and 31)) + (rb xor rc xor rd) + re + w[i] + K4
            re = rd
            rd = rc
            rc = (rb shl 30) or (rb shr 2 and 1073741823)
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

        private val rw = IntArray(80)
        private val rmb = ByteArray(64)
        private val rr = intArrayOf(1732584193, -271733879, -1732584194, 271733878, -1009589776)
        private val padding = byteArrayOf(
            -128, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        )
    }
}
