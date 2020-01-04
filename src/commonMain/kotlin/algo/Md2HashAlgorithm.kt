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

import kotlin.experimental.xor

import org.cryptokt.forEachSegment

/**
 * The first in the MD series by Ronald Rivest. It has a digest size of 128 bits. It has been
 * considered broken since 2004.
 */
public class Md2HashAlgorithm : HashAlgorithm() {

    private var mo = 0
    private var icl: Byte = 0
    private var dcl: Byte = 0
    private val imb = ByteArray(16)
    private val dmb = ByteArray(16)
    private val ixb = ByteArray(48)
    private val dxb = ByteArray(48)
    private val icb = ByteArray(16)
    private val dcb = ByteArray(16)

    init {
        reset()
    }

    public override fun input(buffer: ByteArray, offset: Int, length: Int) {
        mo = forEachSegment(
            imb, mo,
            buffer, offset, length,
            {
                icl = updateChecksum(icl, icb, imb)
                transformBlock(ixb, imb)
            }
        )
    }

    public override fun digest(output: ByteArray, offset: Int): ByteArray
    {
        imb.copyInto(dmb)
        ixb.copyInto(dxb)
        icb.copyInto(dcb)
        dcl = icl

        //
        // APPEND PADDING
        //

        val paddingValue = (16 - mo).toByte()
        var paddingIndex = mo

        while (16 > paddingIndex)
            dmb[paddingIndex++] = paddingValue

        dcl = updateChecksum(dcl, dcb, dmb)
        transformBlock(dxb, dmb)

        //
        // APPEND CHECKSUM
        //

        transformBlock(dxb, dcb)

        return dxb.copyInto(output, offset, 0, 16)
    }

    public override fun reset() {
        mo = 0
        rmb.copyInto(imb)
        rmb.copyInto(dmb)
        rxb.copyInto(ixb)
        rxb.copyInto(dxb)
        rcb.copyInto(icb)
        rcb.copyInto(dcb)
        icl = 0
        dcl = 0
    }

    private fun updateChecksum(cl: Byte, cb: ByteArray, mb: ByteArray): Byte {

        cb[0] = s[(mb[0] xor cl).toInt() and 255] xor cb[0]
        cb[1] = s[(mb[1] xor cb[0]).toInt() and 255] xor cb[1]
        cb[2] = s[(mb[2] xor cb[1]).toInt() and 255] xor cb[2]
        cb[3] = s[(mb[3] xor cb[2]).toInt() and 255] xor cb[3]
        cb[4] = s[(mb[4] xor cb[3]).toInt() and 255] xor cb[4]
        cb[5] = s[(mb[5] xor cb[4]).toInt() and 255] xor cb[5]
        cb[6] = s[(mb[6] xor cb[5]).toInt() and 255] xor cb[6]
        cb[7] = s[(mb[7] xor cb[6]).toInt() and 255] xor cb[7]
        cb[8] = s[(mb[8] xor cb[7]).toInt() and 255] xor cb[8]
        cb[9] = s[(mb[9] xor cb[8]).toInt() and 255] xor cb[9]
        cb[10] = s[(mb[10] xor cb[9]).toInt() and 255] xor cb[10]
        cb[11] = s[(mb[11] xor cb[10]).toInt() and 255] xor cb[11]
        cb[12] = s[(mb[12] xor cb[11]).toInt() and 255] xor cb[12]
        cb[13] = s[(mb[13] xor cb[12]).toInt() and 255] xor cb[13]
        cb[14] = s[(mb[14] xor cb[13]).toInt() and 255] xor cb[14]
        cb[15] = s[(mb[15] xor cb[14]).toInt() and 255] xor cb[15]

        return cb[15]
    }

    private fun transformBlock(xb: ByteArray, mb: ByteArray) {

        for (j in 0..15) {
            xb[16 + j] = mb[j]
            xb[32 + j] = xb[16 + j] xor xb[j]
        }

        var t = 0

        for (j in 0..17) {
            for (k in 0..47) {
                xb[k] = xb[k] xor s[t]
                t = xb[k].toInt().and(255)
            }
            t = (t + j).rem(256)
        }
    }

    public override val length: Int = 16

    public override val size: Int = 128

    private companion object {

        private val rcb = ByteArray(16)
        private val rmb = ByteArray(16)
        private val rxb = ByteArray(48)

        private val s = byteArrayOf(
            41, 46, 67, -55, -94, -40, 124, 1, 61, 54, 84, -95, -20, -16, 6, 19, 98, -89, 5,
            -13, -64, -57, 115, -116, -104, -109, 43, -39, -68, 76, -126, -54, 30, -101, 87, 60,
            -3, -44, -32, 22, 103, 66, 111, 24, -118, 23, -27, 18, -66, 78, -60, -42, -38, -98,
            -34, 73, -96, -5, -11, -114, -69, 47, -18, 122, -87, 104, 121, -111, 21, -78, 7, 63,
            -108, -62, 16, -119, 11, 34, 95, 33, -128, 127, 93, -102, 90, -112, 50, 39, 53, 62,
            -52, -25, -65, -9, -105, 3, -1, 25, 48, -77, 72, -91, -75, -47, -41, 94, -110, 42,
            -84, 86, -86, -58, 79, -72, 56, -46, -106, -92, 125, -74, 118, -4, 107, -30, -100,
            116, 4, -15, 69, -99, 112, 89, 100, 113, -121, 32, -122, 91, -49, 101, -26, 45, -88,
            2, 27, 96, 37, -83, -82, -80, -71, -10, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71,
            -93, 35, -35, 81, -81, 58, -61, 92, -7, -50, -70, -59, -22, 38, 44, 83, 13, 110,
            -123, 40, -124, 9, -45, -33, -51, -12, 65, -127, 77, 82, 106, -36, 55, -56, 108,
            -63, -85, -6, 36, -31, 123, 8, 12, -67, -79, 74, 120, -120, -107, -117, -29, 99,
            -24, 109, -23, -53, -43, -2, 59, 0, 29, 57, -14, -17, -73, 14, 102, 88, -48, -28,
            -90, 119, 114, -8, -21, 117, 75, 10, 49, 68, 80, -76, -113, -19, 31, 26, -37, -103,
            -115, 51, -97, 17, -125, 20
        )
    }
}
