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

import org.cryptokt.beUIntAt
import org.cryptokt.forEachSegment
import org.cryptokt.set
import org.cryptokt.ubyteAt

/**
 * The first formally published version of the U.S. Secure Hash Algorithm. It has a digest size
 * of 160 bits. It has had progressively diminished levels of security beginning in 2010 and was
 * fully broken in 2019.
 */
@ExperimentalStdlibApi
@ExperimentalUnsignedTypes
public class Sha1HashAlgorithm : HashAlgorithm() {

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
        dr.e = ir.e
        dr.h0 = ir.h0
        dr.h1 = ir.h1
        dr.h2 = ir.h2
        dr.h3 = ir.h3
        dr.h4 = ir.h4

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

        dmb[56] = ms.ubyteAt(0)
        dmb[57] = ms.ubyteAt(1)
        dmb[58] = ms.ubyteAt(2)
        dmb[59] = ms.ubyteAt(3)
        dmb[60] = ms.ubyteAt(4)
        dmb[61] = ms.ubyteAt(5)
        dmb[62] = ms.ubyteAt(6)
        dmb[63] = ms.ubyteAt(7)

        //
        // TRANSFORM PADDING + LENGTH
        //

        transformBlock(dr, dmb)

        //
        // SET OUTPUT
        //

        output[0 + offset] = dr.h0.ubyteAt(0).toByte()
        output[1 + offset] = dr.h0.ubyteAt(1).toByte()
        output[2 + offset] = dr.h0.ubyteAt(2).toByte()
        output[3 + offset] = dr.h0.ubyteAt(3).toByte()
        output[4 + offset] = dr.h1.ubyteAt(0).toByte()
        output[5 + offset] = dr.h1.ubyteAt(1).toByte()
        output[6 + offset] = dr.h1.ubyteAt(2).toByte()
        output[7 + offset] = dr.h1.ubyteAt(3).toByte()
        output[8 + offset] = dr.h2.ubyteAt(0).toByte()
        output[9 + offset] = dr.h2.ubyteAt(1).toByte()
        output[10 + offset] = dr.h2.ubyteAt(2).toByte()
        output[11 + offset] = dr.h2.ubyteAt(3).toByte()
        output[12 + offset] = dr.h3.ubyteAt(0).toByte()
        output[13 + offset] = dr.h3.ubyteAt(1).toByte()
        output[14 + offset] = dr.h3.ubyteAt(2).toByte()
        output[15 + offset] = dr.h3.ubyteAt(3).toByte()
        output[16 + offset] = dr.h4.ubyteAt(0).toByte()
        output[17 + offset] = dr.h4.ubyteAt(1).toByte()
        output[18 + offset] = dr.h4.ubyteAt(2).toByte()
        output[19 + offset] = dr.h4.ubyteAt(3).toByte()

        return output
    }

    public override fun reset() {
        mo = 0
        ms = 0UL
        imb[blockRange] = 0x00U
        dmb[blockRange] = 0x00U
        ir.a = H0
        ir.b = H1
        ir.c = H2
        ir.d = H3
        ir.e = H4
        ir.h0 = H0
        ir.h1 = H1
        ir.h2 = H2
        ir.h3 = H3
        ir.h4 = H4
        dr.a = H0
        dr.b = H1
        dr.c = H2
        dr.d = H3
        dr.e = H4
        dr.h0 = H0
        dr.h1 = H1
        dr.h2 = H2
        dr.h3 = H3
        dr.h4 = H4
    }

    private fun transformBlock(r: Registers, mb: UByteArray) {

        var temp: UInt

        val w0 = mb.beUIntAt(0)
        val w1 = mb.beUIntAt(4)
        val w2 = mb.beUIntAt(8)
        val w3 = mb.beUIntAt(12)
        val w4 = mb.beUIntAt(16)
        val w5 = mb.beUIntAt(20)
        val w6 = mb.beUIntAt(24)
        val w7 = mb.beUIntAt(28)
        val w8 = mb.beUIntAt(32)
        val w9 = mb.beUIntAt(36)
        val w10 = mb.beUIntAt(40)
        val w11 = mb.beUIntAt(44)
        val w12 = mb.beUIntAt(48)
        val w13 = mb.beUIntAt(52)
        val w14 = mb.beUIntAt(56)
        val w15 = mb.beUIntAt(60)
        val w16 = (w13 xor w8 xor w2 xor w0).rotateLeft(1)
        val w17 = (w14 xor w9 xor w3 xor w1).rotateLeft(1)
        val w18 = (w15 xor w10 xor w4 xor w2).rotateLeft(1)
        val w19 = (w16 xor w11 xor w5 xor w3).rotateLeft(1)
        val w20 = (w17 xor w12 xor w6 xor w4).rotateLeft(1)
        val w21 = (w18 xor w13 xor w7 xor w5).rotateLeft(1)
        val w22 = (w19 xor w14 xor w8 xor w6).rotateLeft(1)
        val w23 = (w20 xor w15 xor w9 xor w7).rotateLeft(1)
        val w24 = (w21 xor w16 xor w10 xor w8).rotateLeft(1)
        val w25 = (w22 xor w17 xor w11 xor w9).rotateLeft(1)
        val w26 = (w23 xor w18 xor w12 xor w10).rotateLeft(1)
        val w27 = (w24 xor w19 xor w13 xor w11).rotateLeft(1)
        val w28 = (w25 xor w20 xor w14 xor w12).rotateLeft(1)
        val w29 = (w26 xor w21 xor w15 xor w13).rotateLeft(1)
        val w30 = (w27 xor w22 xor w16 xor w14).rotateLeft(1)
        val w31 = (w28 xor w23 xor w17 xor w15).rotateLeft(1)
        val w32 = (w29 xor w24 xor w18 xor w16).rotateLeft(1)
        val w33 = (w30 xor w25 xor w19 xor w17).rotateLeft(1)
        val w34 = (w31 xor w26 xor w20 xor w18).rotateLeft(1)
        val w35 = (w32 xor w27 xor w21 xor w19).rotateLeft(1)
        val w36 = (w33 xor w28 xor w22 xor w20).rotateLeft(1)
        val w37 = (w34 xor w29 xor w23 xor w21).rotateLeft(1)
        val w38 = (w35 xor w30 xor w24 xor w22).rotateLeft(1)
        val w39 = (w36 xor w31 xor w25 xor w23).rotateLeft(1)
        val w40 = (w37 xor w32 xor w26 xor w24).rotateLeft(1)
        val w41 = (w38 xor w33 xor w27 xor w25).rotateLeft(1)
        val w42 = (w39 xor w34 xor w28 xor w26).rotateLeft(1)
        val w43 = (w40 xor w35 xor w29 xor w27).rotateLeft(1)
        val w44 = (w41 xor w36 xor w30 xor w28).rotateLeft(1)
        val w45 = (w42 xor w37 xor w31 xor w29).rotateLeft(1)
        val w46 = (w43 xor w38 xor w32 xor w30).rotateLeft(1)
        val w47 = (w44 xor w39 xor w33 xor w31).rotateLeft(1)
        val w48 = (w45 xor w40 xor w34 xor w32).rotateLeft(1)
        val w49 = (w46 xor w41 xor w35 xor w33).rotateLeft(1)
        val w50 = (w47 xor w42 xor w36 xor w34).rotateLeft(1)
        val w51 = (w48 xor w43 xor w37 xor w35).rotateLeft(1)
        val w52 = (w49 xor w44 xor w38 xor w36).rotateLeft(1)
        val w53 = (w50 xor w45 xor w39 xor w37).rotateLeft(1)
        val w54 = (w51 xor w46 xor w40 xor w38).rotateLeft(1)
        val w55 = (w52 xor w47 xor w41 xor w39).rotateLeft(1)
        val w56 = (w53 xor w48 xor w42 xor w40).rotateLeft(1)
        val w57 = (w54 xor w49 xor w43 xor w41).rotateLeft(1)
        val w58 = (w55 xor w50 xor w44 xor w42).rotateLeft(1)
        val w59 = (w56 xor w51 xor w45 xor w43).rotateLeft(1)
        val w60 = (w57 xor w52 xor w46 xor w44).rotateLeft(1)
        val w61 = (w58 xor w53 xor w47 xor w45).rotateLeft(1)
        val w62 = (w59 xor w54 xor w48 xor w46).rotateLeft(1)
        val w63 = (w60 xor w55 xor w49 xor w47).rotateLeft(1)
        val w64 = (w61 xor w56 xor w50 xor w48).rotateLeft(1)
        val w65 = (w62 xor w57 xor w51 xor w49).rotateLeft(1)
        val w66 = (w63 xor w58 xor w52 xor w50).rotateLeft(1)
        val w67 = (w64 xor w59 xor w53 xor w51).rotateLeft(1)
        val w68 = (w65 xor w60 xor w54 xor w52).rotateLeft(1)
        val w69 = (w66 xor w61 xor w55 xor w53).rotateLeft(1)
        val w70 = (w67 xor w62 xor w56 xor w54).rotateLeft(1)
        val w71 = (w68 xor w63 xor w57 xor w55).rotateLeft(1)
        val w72 = (w69 xor w64 xor w58 xor w56).rotateLeft(1)
        val w73 = (w70 xor w65 xor w59 xor w57).rotateLeft(1)
        val w74 = (w71 xor w66 xor w60 xor w58).rotateLeft(1)
        val w75 = (w72 xor w67 xor w61 xor w59).rotateLeft(1)
        val w76 = (w73 xor w68 xor w62 xor w60).rotateLeft(1)
        val w77 = (w74 xor w69 xor w63 xor w61).rotateLeft(1)
        val w78 = (w75 xor w70 xor w64 xor w62).rotateLeft(1)
        val w79 = (w76 xor w71 xor w65 xor w63).rotateLeft(1)

        r.a = r.h0
        r.b = r.h1
        r.c = r.h2
        r.d = r.h3
        r.e = r.h4

        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w0 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w1 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w2 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w3 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w4 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w5 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w6 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w7 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w8 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w9 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w10 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w11 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w12 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w13 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w14 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w15 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w16 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w17 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w18 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f1(r.b, r.c, r.d) + r.e + w19 + K1
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w20 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w21 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w22 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w23 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w24 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w25 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w26 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w27 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w28 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w29 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w30 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w31 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w32 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w33 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w34 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w35 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w36 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w37 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w38 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w39 + K2
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w40 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w41 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w42 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w43 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w44 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w45 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w46 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w47 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w48 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w49 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w50 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w51 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w52 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w53 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w54 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w55 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w56 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w57 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w58 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f3(r.b, r.c, r.d) + r.e + w59 + K3
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w60 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w61 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w62 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w63 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w64 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w65 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w66 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w67 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w68 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w69 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w70 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w71 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w72 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w73 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w74 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w75 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w76 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w77 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w78 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp
        temp = r.a.rotateLeft(5) + f24(r.b, r.c, r.d) + r.e + w79 + K4
        r.e = r.d
        r.d = r.c
        r.c = r.b.rotateLeft(30)
        r.b = r.a
        r.a = temp

        r.h0 += r.a
        r.h1 += r.b
        r.h2 += r.c
        r.h3 += r.d
        r.h4 += r.e
    }

    public override val length: Int = 20

    public override val size: Int = 160

    private companion object {

        private data class Registers(
            var a: UInt = H0,
            var b: UInt = H1,
            var c: UInt = H2,
            var d: UInt = H3,
            var e: UInt = H4,
            var h0: UInt = H0,
            var h1: UInt = H1,
            var h2: UInt = H2,
            var h3: UInt = H3,
            var h4: UInt = H4
        )

        private const val H0 = 0x67452301U
        private const val H1 = 0xEFCDAB89U
        private const val H2 = 0x98BADCFEU
        private const val H3 = 0x10325476U
        private const val H4 = 0xC3D2E1F0U
        private const val K1 = 0x5A827999U
        private const val K2 = 0x6ED9EBA1U
        private const val K3 = 0x8F1BBCDCU
        private const val K4 = 0xCA62C1D6U

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

        private fun f1(b: UInt, c: UInt, d: UInt) =
            (b and c) or (b.inv() and d)

        private fun f24(b: UInt, c: UInt, d: UInt) =
            b xor c xor d

        private fun f3(b: UInt, c: UInt, d: UInt) =
            (b and c) or (b and d) or (c and d)
    }
}
