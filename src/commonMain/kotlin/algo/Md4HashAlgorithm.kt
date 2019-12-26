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
 * The second in the MD series by Ronald Rivest. It has a digest size of 128 bits. It has been
 * considered broken since 1995.
 */
@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
public class Md4HashAlgorithm : HashAlgorithm() {

    private var mo = 0
    private var ms = 0UL
    private val imb = UByteArray(64)
    private val dmb = UByteArray(64)
    private val ir = Registers()
    private val dr = Registers()

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

        return output
    }

    public override fun reset() {
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

        r.a = r1(r.a, r.b, r.c, r.d, w0, 3)
        r.d = r1(r.d, r.a, r.b, r.c, w1, 7)
        r.c = r1(r.c, r.d, r.a, r.b, w2, 11)
        r.b = r1(r.b, r.c, r.d, r.a, w3, 19)
        r.a = r1(r.a, r.b, r.c, r.d, w4, 3)
        r.d = r1(r.d, r.a, r.b, r.c, w5, 7)
        r.c = r1(r.c, r.d, r.a, r.b, w6, 11)
        r.b = r1(r.b, r.c, r.d, r.a, w7, 19)
        r.a = r1(r.a, r.b, r.c, r.d, w8, 3)
        r.d = r1(r.d, r.a, r.b, r.c, w9, 7)
        r.c = r1(r.c, r.d, r.a, r.b, w10, 11)
        r.b = r1(r.b, r.c, r.d, r.a, w11, 19)
        r.a = r1(r.a, r.b, r.c, r.d, w12, 3)
        r.d = r1(r.d, r.a, r.b, r.c, w13, 7)
        r.c = r1(r.c, r.d, r.a, r.b, w14, 11)
        r.b = r1(r.b, r.c, r.d, r.a, w15, 19)

        //
        // ROUND 2
        //

        r.a = r2(r.a, r.b, r.c, r.d, w0, 3)
        r.d = r2(r.d, r.a, r.b, r.c, w4, 5)
        r.c = r2(r.c, r.d, r.a, r.b, w8, 9)
        r.b = r2(r.b, r.c, r.d, r.a, w12, 13)
        r.a = r2(r.a, r.b, r.c, r.d, w1, 3)
        r.d = r2(r.d, r.a, r.b, r.c, w5, 5)
        r.c = r2(r.c, r.d, r.a, r.b, w9, 9)
        r.b = r2(r.b, r.c, r.d, r.a, w13, 13)
        r.a = r2(r.a, r.b, r.c, r.d, w2, 3)
        r.d = r2(r.d, r.a, r.b, r.c, w6, 5)
        r.c = r2(r.c, r.d, r.a, r.b, w10, 9)
        r.b = r2(r.b, r.c, r.d, r.a, w14, 13)
        r.a = r2(r.a, r.b, r.c, r.d, w3, 3)
        r.d = r2(r.d, r.a, r.b, r.c, w7, 5)
        r.c = r2(r.c, r.d, r.a, r.b, w11, 9)
        r.b = r2(r.b, r.c, r.d, r.a, w15, 13)

        //
        // ROUND 3
        //

        r.a = r3(r.a, r.b, r.c, r.d, w0, 3)
        r.d = r3(r.d, r.a, r.b, r.c, w8, 9)
        r.c = r3(r.c, r.d, r.a, r.b, w4, 11)
        r.b = r3(r.b, r.c, r.d, r.a, w12, 15)
        r.a = r3(r.a, r.b, r.c, r.d, w2, 3)
        r.d = r3(r.d, r.a, r.b, r.c, w10, 9)
        r.c = r3(r.c, r.d, r.a, r.b, w6, 11)
        r.b = r3(r.b, r.c, r.d, r.a, w14, 15)
        r.a = r3(r.a, r.b, r.c, r.d, w1, 3)
        r.d = r3(r.d, r.a, r.b, r.c, w9, 9)
        r.c = r3(r.c, r.d, r.a, r.b, w5, 11)
        r.b = r3(r.b, r.c, r.d, r.a, w13, 15)
        r.a = r3(r.a, r.b, r.c, r.d, w3, 3)
        r.d = r3(r.d, r.a, r.b, r.c, w11, 9)
        r.c = r3(r.c, r.d, r.a, r.b, w7, 11)
        r.b = r3(r.b, r.c, r.d, r.a, w15, 15)

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

        private fun r1(p1: UInt, p2: UInt, p3: UInt, p4: UInt, p5: UInt, p6: Int) =
            (p1 + ((p2 and p3) or (p2.inv() and p4)) + p5).rotateLeft(p6)

        private fun r2(p1: UInt, p2: UInt, p3: UInt, p4: UInt, p5: UInt, p6: Int) =
            (p1 + ((p2 and p3) or (p2 and p4) or (p3 and p4)) + p5 + 0x5A827999U).rotateLeft(p6)

        private fun r3(p1: UInt, p2: UInt, p3: UInt, p4: UInt, p5: UInt, p6: Int) =
            (p1 + (p2 xor p3 xor p4) + p5 + 0x6ED9EBA1U).rotateLeft(p6)
    }
}
