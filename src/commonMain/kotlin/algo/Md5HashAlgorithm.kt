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

import org.cryptokt.leUIntAt
import org.cryptokt.forEachSegment
import org.cryptokt.set
import org.cryptokt.ubyteAt

/**
 * The third in the MD series by Ronald Rivest. It has a digest size of 128 bits. It has been
 * considered broken since 2013.
 */
@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
public class Md5HashAlgorithm : HashAlgorithm() {

    private var mo = 0
    private var ms = 0UL
    private val imb = UByteArray(64)
    private val dmb = UByteArray(64)
    private val ir = Registers()
    private val dr = Registers()

    init {
        clear()
    }

    public override fun input(buffer: ByteArray, offset: Int, length: Int) {
        mo = forEachSegment(
            imb, mo,
            buffer, offset, length,
            {
                transformBlock(ir, imb)
            }
        )
        ms += (length * 8).toULong()
    }

    public override fun digest(output: ByteArray, offset: Int): ByteArray {

        //
        // COPY STATE
        //

        imb.copyInto(dmb)
        dr.a = ir.a
        dr.b = ir.b
        dr.c = ir.c
        dr.d = ir.d

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

        dmb[56] = ms.ubyteAt(7)
        dmb[57] = ms.ubyteAt(6)
        dmb[58] = ms.ubyteAt(5)
        dmb[59] = ms.ubyteAt(4)
        dmb[60] = ms.ubyteAt(3)
        dmb[61] = ms.ubyteAt(2)
        dmb[62] = ms.ubyteAt(1)
        dmb[63] = ms.ubyteAt(0)

        //
        // TRANSFORM PADDING + LENGTH
        //

        transformBlock(dr, dmb)

        //
        // SET OUTPUT
        //

        output[0 + offset] = dr.a.ubyteAt(3).toByte()
        output[1 + offset] = dr.a.ubyteAt(2).toByte()
        output[2 + offset] = dr.a.ubyteAt(1).toByte()
        output[3 + offset] = dr.a.ubyteAt(0).toByte()
        output[4 + offset] = dr.b.ubyteAt(3).toByte()
        output[5 + offset] = dr.b.ubyteAt(2).toByte()
        output[6 + offset] = dr.b.ubyteAt(1).toByte()
        output[7 + offset] = dr.b.ubyteAt(0).toByte()
        output[8 + offset] = dr.c.ubyteAt(3).toByte()
        output[9 + offset] = dr.c.ubyteAt(2).toByte()
        output[10 + offset] = dr.c.ubyteAt(1).toByte()
        output[11 + offset] = dr.c.ubyteAt(0).toByte()
        output[12 + offset] = dr.d.ubyteAt(3).toByte()
        output[13 + offset] = dr.d.ubyteAt(2).toByte()
        output[14 + offset] = dr.d.ubyteAt(1).toByte()
        output[15 + offset] = dr.d.ubyteAt(0).toByte()

        clear()

        return output
    }

    private fun clear() {
        mo = 0
        ms = 0UL
        imb[blockRange] = 0x00U
        dmb[blockRange] = 0x00U
        ir.a = A
        ir.b = B
        ir.c = C
        ir.d = D
        dr.a = A
        dr.b = B
        dr.c = C
        dr.d = D
    }

    private fun transformBlock(r: Registers, mb: UByteArray) {

        val aa = r.a
        val bb = r.b
        val cc = r.c
        val dd = r.d

        //
        // READ BLOCK
        //

        val w0 = mb.leUIntAt(0)
        val w1 = mb.leUIntAt(4)
        val w2 = mb.leUIntAt(8)
        val w3 = mb.leUIntAt(12)
        val w4 = mb.leUIntAt(16)
        val w5 = mb.leUIntAt(20)
        val w6 = mb.leUIntAt(24)
        val w7 = mb.leUIntAt(28)
        val w8 = mb.leUIntAt(32)
        val w9 = mb.leUIntAt(36)
        val w10 = mb.leUIntAt(40)
        val w11 = mb.leUIntAt(44)
        val w12 = mb.leUIntAt(48)
        val w13 = mb.leUIntAt(52)
        val w14 = mb.leUIntAt(56)
        val w15 = mb.leUIntAt(60)

        //
        // ROUND 1
        //

        r.a = r1(r.a, r.b, r.c, r.d, w0, 0xD76AA478U, 7)
        r.d = r1(r.d, r.a, r.b, r.c, w1, 0xE8C7B756U, 12)
        r.c = r1(r.c, r.d, r.a, r.b, w2, 0x242070DBU, 17)
        r.b = r1(r.b, r.c, r.d, r.a, w3, 0xC1BDCEEEU, 22)
        r.a = r1(r.a, r.b, r.c, r.d, w4, 0xF57C0FAFU, 7)
        r.d = r1(r.d, r.a, r.b, r.c, w5, 0x4787C62AU, 12)
        r.c = r1(r.c, r.d, r.a, r.b, w6, 0xA8304613U, 17)
        r.b = r1(r.b, r.c, r.d, r.a, w7, 0xFD469501U, 22)
        r.a = r1(r.a, r.b, r.c, r.d, w8, 0x698098D8U, 7)
        r.d = r1(r.d, r.a, r.b, r.c, w9, 0x8B44F7AFU, 12)
        r.c = r1(r.c, r.d, r.a, r.b, w10, 0xFFFF5BB1U, 17)
        r.b = r1(r.b, r.c, r.d, r.a, w11, 0x895CD7BEU, 22)
        r.a = r1(r.a, r.b, r.c, r.d, w12, 0x6B901122U, 7)
        r.d = r1(r.d, r.a, r.b, r.c, w13, 0xFD987193U, 12)
        r.c = r1(r.c, r.d, r.a, r.b, w14, 0xA679438EU, 17)
        r.b = r1(r.b, r.c, r.d, r.a, w15, 0x49B40821U, 22)

        //
        // ROUND 2
        //

        r.a = r2(r.a, r.b, r.c, r.d, w1, 0xF61E2562U, 5)
        r.d = r2(r.d, r.a, r.b, r.c, w6, 0xC040B340U, 9)
        r.c = r2(r.c, r.d, r.a, r.b, w11, 0x265E5A51U, 14)
        r.b = r2(r.b, r.c, r.d, r.a, w0, 0xE9B6C7AAU, 20)
        r.a = r2(r.a, r.b, r.c, r.d, w5, 0xD62F105DU, 5)
        r.d = r2(r.d, r.a, r.b, r.c, w10, 0x02441453U, 9)
        r.c = r2(r.c, r.d, r.a, r.b, w15, 0xD8A1E681U, 14)
        r.b = r2(r.b, r.c, r.d, r.a, w4, 0xE7D3FBC8U, 20)
        r.a = r2(r.a, r.b, r.c, r.d, w9, 0x21E1CDE6U, 5)
        r.d = r2(r.d, r.a, r.b, r.c, w14, 0xC33707D6U, 9)
        r.c = r2(r.c, r.d, r.a, r.b, w3, 0xF4D50D87U, 14)
        r.b = r2(r.b, r.c, r.d, r.a, w8, 0x455A14EDU, 20)
        r.a = r2(r.a, r.b, r.c, r.d, w13, 0xA9E3E905U, 5)
        r.d = r2(r.d, r.a, r.b, r.c, w2, 0xFCEFA3F8U, 9)
        r.c = r2(r.c, r.d, r.a, r.b, w7, 0x676F02D9U, 14)
        r.b = r2(r.b, r.c, r.d, r.a, w12, 0x8D2A4C8AU, 20)

        //
        // ROUND 3
        //

        r.a = r3(r.a, r.b, r.c, r.d, w5, 0xFFFA3942U, 4)
        r.d = r3(r.d, r.a, r.b, r.c, w8, 0x8771F681U, 11)
        r.c = r3(r.c, r.d, r.a, r.b, w11, 0x6D9D6122U, 16)
        r.b = r3(r.b, r.c, r.d, r.a, w14, 0xFDE5380CU, 23)
        r.a = r3(r.a, r.b, r.c, r.d, w1, 0xA4BEEA44U, 4)
        r.d = r3(r.d, r.a, r.b, r.c, w4, 0x4BDECFA9U, 11)
        r.c = r3(r.c, r.d, r.a, r.b, w7, 0xF6BB4B60U, 16)
        r.b = r3(r.b, r.c, r.d, r.a, w10, 0xBEBFBC70U, 23)
        r.a = r3(r.a, r.b, r.c, r.d, w13, 0x289B7EC6U, 4)
        r.d = r3(r.d, r.a, r.b, r.c, w0, 0xEAA127FAU, 11)
        r.c = r3(r.c, r.d, r.a, r.b, w3, 0xD4EF3085U, 16)
        r.b = r3(r.b, r.c, r.d, r.a, w6, 0x04881D05U, 23)
        r.a = r3(r.a, r.b, r.c, r.d, w9, 0xD9D4D039U, 4)
        r.d = r3(r.d, r.a, r.b, r.c, w12, 0xE6DB99E5U, 11)
        r.c = r3(r.c, r.d, r.a, r.b, w15, 0x1FA27CF8U, 16)
        r.b = r3(r.b, r.c, r.d, r.a, w2, 0xC4AC5665U, 23)

        //
        // ROUND 4
        //

        r.a = r4(r.a, r.b, r.c, r.d, w0, 0xF4292244U, 6)
        r.d = r4(r.d, r.a, r.b, r.c, w7, 0x432AFF97U, 10)
        r.c = r4(r.c, r.d, r.a, r.b, w14, 0xAB9423A7U, 15)
        r.b = r4(r.b, r.c, r.d, r.a, w5, 0xFC93A039U, 21)
        r.a = r4(r.a, r.b, r.c, r.d, w12, 0x655B59C3U, 6)
        r.d = r4(r.d, r.a, r.b, r.c, w3, 0x8F0CCC92U, 10)
        r.c = r4(r.c, r.d, r.a, r.b, w10, 0xFFEFF47DU, 15)
        r.b = r4(r.b, r.c, r.d, r.a, w1, 0x85845DD1U, 21)
        r.a = r4(r.a, r.b, r.c, r.d, w8, 0x6FA87E4FU, 6)
        r.d = r4(r.d, r.a, r.b, r.c, w15, 0xFE2CE6E0U, 10)
        r.c = r4(r.c, r.d, r.a, r.b, w6, 0xA3014314U, 15)
        r.b = r4(r.b, r.c, r.d, r.a, w13, 0x4E0811A1U, 21)
        r.a = r4(r.a, r.b, r.c, r.d, w4, 0xF7537E82U, 6)
        r.d = r4(r.d, r.a, r.b, r.c, w11, 0xBD3AF235U, 10)
        r.c = r4(r.c, r.d, r.a, r.b, w2, 0x2AD7D2BBU, 15)
        r.b = r4(r.b, r.c, r.d, r.a, w9, 0xEB86D391U, 21)

        r.a += aa
        r.b += bb
        r.c += cc
        r.d += dd
    }

    public override val length: Int = 16

    public override val size: Int = 128

    private companion object {

        private data class Registers(
            var a: UInt = A,
            var b: UInt = B,
            var c: UInt = C,
            var d: UInt = D
        )

        private const val A = 0x67452301U
        private const val B = 0xEFCDAB89U
        private const val C = 0x98BADCFEU
        private const val D = 0x10325476U

        private val blockRange = 0..63

        private val padding = ubyteArrayOf(
            0x80U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U
        )

        private fun r1(a: UInt, b: UInt, c: UInt, d: UInt, x: UInt, t: UInt, s: Int) =
            b + (a + ((b and c) or (b.inv() and d)) + x + t).rotateLeft(s)

        private fun r2(a: UInt, b: UInt, c: UInt, d: UInt, x: UInt, t: UInt, s: Int) =
            b + (a + ((b and d) or (c and d.inv())) + x + t).rotateLeft(s)

        private fun r3(a: UInt, b: UInt, c: UInt, d: UInt, x: UInt, t: UInt, s: Int) =
            b + (a + (b xor c xor d) + x + t).rotateLeft(s)

        private fun r4(a: UInt, b: UInt, c: UInt, d: UInt, x: UInt, t: UInt, s: Int) =
            b + (a + (c xor (b or d.inv())) + x + t).rotateLeft(s)
    }
}
