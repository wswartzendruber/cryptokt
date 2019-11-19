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

import org.cryptokt.clear
import org.cryptokt.forEachSegment

/**
 * The first in the MD series by Ronald Rivest. It has a digest size of 128 bits. It has been
 * considered broken since 2004.
 */
@ExperimentalUnsignedTypes
public class Md2 : Hash() {

    private var mo = 0
    private val imb = UByteArray(16)
    private val dmb = UByteArray(16)
    private val ixb = UByteArray(48)
    private val dxb = UByteArray(48)
    private val ick = Checksum()
    private val dck = Checksum()

    public override fun input(buffer: ByteArray, offset: Int, length: Int) {
        mo = forEachSegment(
            imb, mo,
            buffer, offset, length,
            {
                updateChecksum(ick, imb)
                transformBlock(ixb, imb)
            }
        )
    }

    public override fun digest(output: ByteArray, offset: Int): ByteArray
    {
        imb.copyInto(dmb)
        ixb.copyInto(dxb)
        ick.b.copyInto(dck.b)
        dck.l = ick.l

        //
        // APPEND PADDING
        //

        val paddingValue = (16 - mo).toUByte()

        for (paddingIndex in mo..15)
            dmb[paddingIndex] = paddingValue

        updateChecksum(dck, dmb)
        transformBlock(dxb, dmb)

        //
        // APPEND CHECKSUM
        //

        transformBlock(dxb, dck.b)

        return dxb.asByteArray().copyInto(output, offset, 0, 16)
    }

    public override fun reset() {
        mo = 0
        imb.clear()
        dmb.clear()
        ixb.clear()
        dxb.clear()
        ick.b.clear()
        ick.l = 0U
        dck.b.clear()
        dck.l = 0U
    }

    private fun updateChecksum(ck: Checksum, mb: UByteArray) {
        for (j in 0..15) {
            ck.b[j] = S[mb[j] xor ck.l] xor ck.b[j]
            ck.l = ck.b[j]
        }
    }

    private fun transformBlock(xb: UByteArray, mb: UByteArray) {

        for (j in 0..15) {
            xb[16 + j] = mb[j]
            xb[32 + j] = xb[16 + j] xor xb[j]
        }

        var t = 0

        for (j in 0..17) {
            for (k in 0..47) {
                xb[k] = xb[k] xor S[t]
                t = xb[k].toInt()
            }
            t = (t + j).rem(256)
        }
    }

    private data class Checksum(
        val b: UByteArray = UByteArray(16),
        var l: UByte = 0U
    )

    public override val length: Int = 16

    public override val size: Int = 128

    private companion object {

        private val S = ubyteArrayOf(
            0x29U, 0x2EU, 0x43U, 0xC9U, 0xA2U, 0xD8U, 0x7CU, 0x01U, 0x3DU, 0x36U, 0x54U, 0xA1U,
            0xECU, 0xF0U, 0x06U, 0x13U, 0x62U, 0xA7U, 0x05U, 0xF3U, 0xC0U, 0xC7U, 0x73U, 0x8CU,
            0x98U, 0x93U, 0x2BU, 0xD9U, 0xBCU, 0x4CU, 0x82U, 0xCAU, 0x1EU, 0x9BU, 0x57U, 0x3CU,
            0xFDU, 0xD4U, 0xE0U, 0x16U, 0x67U, 0x42U, 0x6FU, 0x18U, 0x8AU, 0x17U, 0xE5U, 0x12U,
            0xBEU, 0x4EU, 0xC4U, 0xD6U, 0xDAU, 0x9EU, 0xDEU, 0x49U, 0xA0U, 0xFBU, 0xF5U, 0x8EU,
            0xBBU, 0x2FU, 0xEEU, 0x7AU, 0xA9U, 0x68U, 0x79U, 0x91U, 0x15U, 0xB2U, 0x07U, 0x3FU,
            0x94U, 0xC2U, 0x10U, 0x89U, 0x0BU, 0x22U, 0x5FU, 0x21U, 0x80U, 0x7FU, 0x5DU, 0x9AU,
            0x5AU, 0x90U, 0x32U, 0x27U, 0x35U, 0x3EU, 0xCCU, 0xE7U, 0xBFU, 0xF7U, 0x97U, 0x03U,
            0xFFU, 0x19U, 0x30U, 0xB3U, 0x48U, 0xA5U, 0xB5U, 0xD1U, 0xD7U, 0x5EU, 0x92U, 0x2AU,
            0xACU, 0x56U, 0xAAU, 0xC6U, 0x4FU, 0xB8U, 0x38U, 0xD2U, 0x96U, 0xA4U, 0x7DU, 0xB6U,
            0x76U, 0xFCU, 0x6BU, 0xE2U, 0x9CU, 0x74U, 0x04U, 0xF1U, 0x45U, 0x9DU, 0x70U, 0x59U,
            0x64U, 0x71U, 0x87U, 0x20U, 0x86U, 0x5BU, 0xCFU, 0x65U, 0xE6U, 0x2DU, 0xA8U, 0x02U,
            0x1BU, 0x60U, 0x25U, 0xADU, 0xAEU, 0xB0U, 0xB9U, 0xF6U, 0x1CU, 0x46U, 0x61U, 0x69U,
            0x34U, 0x40U, 0x7EU, 0x0FU, 0x55U, 0x47U, 0xA3U, 0x23U, 0xDDU, 0x51U, 0xAFU, 0x3AU,
            0xC3U, 0x5CU, 0xF9U, 0xCEU, 0xBAU, 0xC5U, 0xEAU, 0x26U, 0x2CU, 0x53U, 0x0DU, 0x6EU,
            0x85U, 0x28U, 0x84U, 0x09U, 0xD3U, 0xDFU, 0xCDU, 0xF4U, 0x41U, 0x81U, 0x4DU, 0x52U,
            0x6AU, 0xDCU, 0x37U, 0xC8U, 0x6CU, 0xC1U, 0xABU, 0xFAU, 0x24U, 0xE1U, 0x7BU, 0x08U,
            0x0CU, 0xBDU, 0xB1U, 0x4AU, 0x78U, 0x88U, 0x95U, 0x8BU, 0xE3U, 0x63U, 0xE8U, 0x6DU,
            0xE9U, 0xCBU, 0xD5U, 0xFEU, 0x3BU, 0x00U, 0x1DU, 0x39U, 0xF2U, 0xEFU, 0xB7U, 0x0EU,
            0x66U, 0x58U, 0xD0U, 0xE4U, 0xA6U, 0x77U, 0x72U, 0xF8U, 0xEBU, 0x75U, 0x4BU, 0x0AU,
            0x31U, 0x44U, 0x50U, 0xB4U, 0x8FU, 0xEDU, 0x1FU, 0x1AU, 0xDBU, 0x99U, 0x8DU, 0x33U,
            0x9FU, 0x11U, 0x83U, 0x14U
        )

        private operator fun UByteArray.get(index: UByte) = this[index.toInt()]
    }
}
