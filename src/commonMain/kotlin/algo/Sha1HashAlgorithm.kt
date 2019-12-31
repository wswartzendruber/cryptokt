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
import org.cryptokt.byteAt
import org.cryptokt.forEachSegment
import org.cryptokt.rl
import org.cryptokt.set

/**
 * The first formally published version of the U.S. Secure Hash Algorithm. It has a digest size
 * of 160 bits. It has had progressively diminished levels of security beginning in 2010 and was
 * fully broken in 2019.
 */
@ExperimentalStdlibApi
public class Sha1HashAlgorithm : HashAlgorithm() {

    private var mo = 0
    private var ms = 0L
    private val imb = ByteArray(64)
    private val dmb = ByteArray(64)
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
        ms += (length * 8).toLong()
    }

    public override fun digest(output: ByteArray, offset: Int): ByteArray {

        //
        // COPY STATE
        //

        imb.copyInto(dmb)
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

        dmb[56] = ms.byteAt(0)
        dmb[57] = ms.byteAt(1)
        dmb[58] = ms.byteAt(2)
        dmb[59] = ms.byteAt(3)
        dmb[60] = ms.byteAt(4)
        dmb[61] = ms.byteAt(5)
        dmb[62] = ms.byteAt(6)
        dmb[63] = ms.byteAt(7)

        //
        // TRANSFORM PADDING + LENGTH
        //

        transformBlock(dr, dmb)

        //
        // SET OUTPUT
        //

        output[0 + offset] = dr.h0.byteAt(0)
        output[1 + offset] = dr.h0.byteAt(1)
        output[2 + offset] = dr.h0.byteAt(2)
        output[3 + offset] = dr.h0.byteAt(3)
        output[4 + offset] = dr.h1.byteAt(0)
        output[5 + offset] = dr.h1.byteAt(1)
        output[6 + offset] = dr.h1.byteAt(2)
        output[7 + offset] = dr.h1.byteAt(3)
        output[8 + offset] = dr.h2.byteAt(0)
        output[9 + offset] = dr.h2.byteAt(1)
        output[10 + offset] = dr.h2.byteAt(2)
        output[11 + offset] = dr.h2.byteAt(3)
        output[12 + offset] = dr.h3.byteAt(0)
        output[13 + offset] = dr.h3.byteAt(1)
        output[14 + offset] = dr.h3.byteAt(2)
        output[15 + offset] = dr.h3.byteAt(3)
        output[16 + offset] = dr.h4.byteAt(0)
        output[17 + offset] = dr.h4.byteAt(1)
        output[18 + offset] = dr.h4.byteAt(2)
        output[19 + offset] = dr.h4.byteAt(3)

        return output
    }

    public override fun reset() {
        mo = 0
        ms = 0L
        imb[blockRange] = 0
        dmb[blockRange] = 0
        ir.h0 = H0
        ir.h1 = H1
        ir.h2 = H2
        ir.h3 = H3
        ir.h4 = H4
        dr.h0 = H0
        dr.h1 = H1
        dr.h2 = H2
        dr.h3 = H3
        dr.h4 = H4
    }

    private fun transformBlock(r: Registers, mb: ByteArray) {

        var temp: Int

        val w0 = mb.beIntAt(0)
        val w1 = mb.beIntAt(4)
        val w2 = mb.beIntAt(8)
        val w3 = mb.beIntAt(12)
        val w4 = mb.beIntAt(16)
        val w5 = mb.beIntAt(20)
        val w6 = mb.beIntAt(24)
        val w7 = mb.beIntAt(28)
        val w8 = mb.beIntAt(32)
        val w9 = mb.beIntAt(36)
        val w10 = mb.beIntAt(40)
        val w11 = mb.beIntAt(44)
        val w12 = mb.beIntAt(48)
        val w13 = mb.beIntAt(52)
        val w14 = mb.beIntAt(56)
        val w15 = mb.beIntAt(60)
        val w16 = (w13 xor w8 xor w2 xor w0) rl 1
        val w17 = (w14 xor w9 xor w3 xor w1) rl 1
        val w18 = (w15 xor w10 xor w4 xor w2) rl 1
        val w19 = (w16 xor w11 xor w5 xor w3) rl 1
        val w20 = (w17 xor w12 xor w6 xor w4) rl 1
        val w21 = (w18 xor w13 xor w7 xor w5) rl 1
        val w22 = (w19 xor w14 xor w8 xor w6) rl 1
        val w23 = (w20 xor w15 xor w9 xor w7) rl 1
        val w24 = (w21 xor w16 xor w10 xor w8) rl 1
        val w25 = (w22 xor w17 xor w11 xor w9) rl 1
        val w26 = (w23 xor w18 xor w12 xor w10) rl 1
        val w27 = (w24 xor w19 xor w13 xor w11) rl 1
        val w28 = (w25 xor w20 xor w14 xor w12) rl 1
        val w29 = (w26 xor w21 xor w15 xor w13) rl 1
        val w30 = (w27 xor w22 xor w16 xor w14) rl 1
        val w31 = (w28 xor w23 xor w17 xor w15) rl 1
        val w32 = (w29 xor w24 xor w18 xor w16) rl 1
        val w33 = (w30 xor w25 xor w19 xor w17) rl 1
        val w34 = (w31 xor w26 xor w20 xor w18) rl 1
        val w35 = (w32 xor w27 xor w21 xor w19) rl 1
        val w36 = (w33 xor w28 xor w22 xor w20) rl 1
        val w37 = (w34 xor w29 xor w23 xor w21) rl 1
        val w38 = (w35 xor w30 xor w24 xor w22) rl 1
        val w39 = (w36 xor w31 xor w25 xor w23) rl 1
        val w40 = (w37 xor w32 xor w26 xor w24) rl 1
        val w41 = (w38 xor w33 xor w27 xor w25) rl 1
        val w42 = (w39 xor w34 xor w28 xor w26) rl 1
        val w43 = (w40 xor w35 xor w29 xor w27) rl 1
        val w44 = (w41 xor w36 xor w30 xor w28) rl 1
        val w45 = (w42 xor w37 xor w31 xor w29) rl 1
        val w46 = (w43 xor w38 xor w32 xor w30) rl 1
        val w47 = (w44 xor w39 xor w33 xor w31) rl 1
        val w48 = (w45 xor w40 xor w34 xor w32) rl 1
        val w49 = (w46 xor w41 xor w35 xor w33) rl 1
        val w50 = (w47 xor w42 xor w36 xor w34) rl 1
        val w51 = (w48 xor w43 xor w37 xor w35) rl 1
        val w52 = (w49 xor w44 xor w38 xor w36) rl 1
        val w53 = (w50 xor w45 xor w39 xor w37) rl 1
        val w54 = (w51 xor w46 xor w40 xor w38) rl 1
        val w55 = (w52 xor w47 xor w41 xor w39) rl 1
        val w56 = (w53 xor w48 xor w42 xor w40) rl 1
        val w57 = (w54 xor w49 xor w43 xor w41) rl 1
        val w58 = (w55 xor w50 xor w44 xor w42) rl 1
        val w59 = (w56 xor w51 xor w45 xor w43) rl 1
        val w60 = (w57 xor w52 xor w46 xor w44) rl 1
        val w61 = (w58 xor w53 xor w47 xor w45) rl 1
        val w62 = (w59 xor w54 xor w48 xor w46) rl 1
        val w63 = (w60 xor w55 xor w49 xor w47) rl 1
        val w64 = (w61 xor w56 xor w50 xor w48) rl 1
        val w65 = (w62 xor w57 xor w51 xor w49) rl 1
        val w66 = (w63 xor w58 xor w52 xor w50) rl 1
        val w67 = (w64 xor w59 xor w53 xor w51) rl 1
        val w68 = (w65 xor w60 xor w54 xor w52) rl 1
        val w69 = (w66 xor w61 xor w55 xor w53) rl 1
        val w70 = (w67 xor w62 xor w56 xor w54) rl 1
        val w71 = (w68 xor w63 xor w57 xor w55) rl 1
        val w72 = (w69 xor w64 xor w58 xor w56) rl 1
        val w73 = (w70 xor w65 xor w59 xor w57) rl 1
        val w74 = (w71 xor w66 xor w60 xor w58) rl 1
        val w75 = (w72 xor w67 xor w61 xor w59) rl 1
        val w76 = (w73 xor w68 xor w62 xor w60) rl 1
        val w77 = (w74 xor w69 xor w63 xor w61) rl 1
        val w78 = (w75 xor w70 xor w64 xor w62) rl 1
        val w79 = (w76 xor w71 xor w65 xor w63) rl 1

        var ra = r.h0
        var rb = r.h1
        var rc = r.h2
        var rd = r.h3
        var re = r.h4

        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w0 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w1 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w2 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w3 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w4 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w5 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w6 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w7 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w8 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w9 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w10 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w11 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w12 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w13 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w14 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w15 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w16 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w17 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w18 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb.inv() and rd)) + re + w19 + K1
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w20 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w21 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w22 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w23 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w24 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w25 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w26 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w27 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w28 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w29 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w30 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w31 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w32 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w33 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w34 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w35 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w36 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w37 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w38 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w39 + K2
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w40 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w41 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w42 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w43 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w44 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w45 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w46 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w47 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w48 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w49 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w50 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w51 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w52 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w53 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w54 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w55 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w56 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w57 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w58 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + ((rb and rc) or (rb and rd) or (rc and rd)) + re + w59 + K3
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w60 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w61 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w62 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w63 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w64 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w65 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w66 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w67 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w68 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w69 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w70 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w71 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w72 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w73 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w74 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w75 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w76 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w77 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w78 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp
        temp = (ra rl 5) + (rb xor rc xor rd) + re + w79 + K4
        re = rd
        rd = rc
        rc = rb rl 30
        rb = ra
        ra = temp

        r.h0 += ra
        r.h1 += rb
        r.h2 += rc
        r.h3 += rd
        r.h4 += re
    }

    public override val length: Int = 20

    public override val size: Int = 160

    private companion object {

        private data class Registers(
            var h0: Int = H0,
            var h1: Int = H1,
            var h2: Int = H2,
            var h3: Int = H3,
            var h4: Int = H4
        )

        private const val H0 = 1732584193
        private const val H1 = -271733879
        private const val H2 = -1732584194
        private const val H3 = 271733878
        private const val H4 = -1009589776
        private const val K1 = 1518500249
        private const val K2 = 1859775393
        private const val K3 = -1894007588
        private const val K4 = -899497514

        private val blockRange = 0..63

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
