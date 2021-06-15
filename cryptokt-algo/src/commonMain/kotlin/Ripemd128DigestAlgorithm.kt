/*
 * SPDX-FileCopyrightText: 2020 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.cryptokt.algo

/**
 * The second formally published version of RIPE's message digest algorithm. This implementation
 * handles RIPEMD-128. The block size is 64 bytes and the digest size is 16 bytes.
 */
public class Ripemd128DigestAlgorithm : DigestAlgorithm(64, 16) {

    private var ms = 0L
    private val r = cr.copyInto(IntArray(4))
    private val w = cw.copyInto(IntArray(16))

    protected override fun transformBlock(block: ByteArray): Unit {

        //
        // READ BLOCK
        //

        for (i in 0 until 16)
            w[i] = block.leIntAt(4 * i)

        var aa = r[0]
        var bb = r[1]
        var cc = r[2]
        var dd = r[3]
        var aaa = r[0]
        var bbb = r[1]
        var ccc = r[2]
        var ddd = r[3]

        aa = (aa + f(bb, cc, dd) + w[0]) rl 11
        dd = (dd + f(aa, bb, cc) + w[1]) rl 14
        cc = (cc + f(dd, aa, bb) + w[2]) rl 15
        bb = (bb + f(cc, dd, aa) + w[3]) rl 12
        aa = (aa + f(bb, cc, dd) + w[4]) rl 5
        dd = (dd + f(aa, bb, cc) + w[5]) rl 8
        cc = (cc + f(dd, aa, bb) + w[6]) rl 7
        bb = (bb + f(cc, dd, aa) + w[7]) rl 9
        aa = (aa + f(bb, cc, dd) + w[8]) rl 11
        dd = (dd + f(aa, bb, cc) + w[9]) rl 13
        cc = (cc + f(dd, aa, bb) + w[10]) rl 14
        bb = (bb + f(cc, dd, aa) + w[11]) rl 15
        aa = (aa + f(bb, cc, dd) + w[12]) rl 6
        dd = (dd + f(aa, bb, cc) + w[13]) rl 7
        cc = (cc + f(dd, aa, bb) + w[14]) rl 9
        bb = (bb + f(cc, dd, aa) + w[15]) rl 8

        aa = (aa + g(bb, cc, dd) + w[7] + 1518500249) rl 7
        dd = (dd + g(aa, bb, cc) + w[4] + 1518500249) rl 6
        cc = (cc + g(dd, aa, bb) + w[13] + 1518500249) rl 8
        bb = (bb + g(cc, dd, aa) + w[1] + 1518500249) rl 13
        aa = (aa + g(bb, cc, dd) + w[10] + 1518500249) rl 11
        dd = (dd + g(aa, bb, cc) + w[6] + 1518500249) rl 9
        cc = (cc + g(dd, aa, bb) + w[15] + 1518500249) rl 7
        bb = (bb + g(cc, dd, aa) + w[3] + 1518500249) rl 15
        aa = (aa + g(bb, cc, dd) + w[12] + 1518500249) rl 7
        dd = (dd + g(aa, bb, cc) + w[0] + 1518500249) rl 12
        cc = (cc + g(dd, aa, bb) + w[9] + 1518500249) rl 15
        bb = (bb + g(cc, dd, aa) + w[5] + 1518500249) rl 9
        aa = (aa + g(bb, cc, dd) + w[2] + 1518500249) rl 11
        dd = (dd + g(aa, bb, cc) + w[14] + 1518500249) rl 7
        cc = (cc + g(dd, aa, bb) + w[11] + 1518500249) rl 13
        bb = (bb + g(cc, dd, aa) + w[8] + 1518500249) rl 12

        aa = (aa + h(bb, cc, dd) + w[3] + 1859775393) rl 11
        dd = (dd + h(aa, bb, cc) + w[10] + 1859775393) rl 13
        cc = (cc + h(dd, aa, bb) + w[14] + 1859775393) rl 6
        bb = (bb + h(cc, dd, aa) + w[4] + 1859775393) rl 7
        aa = (aa + h(bb, cc, dd) + w[9] + 1859775393) rl 14
        dd = (dd + h(aa, bb, cc) + w[15] + 1859775393) rl 9
        cc = (cc + h(dd, aa, bb) + w[8] + 1859775393) rl 13
        bb = (bb + h(cc, dd, aa) + w[1] + 1859775393) rl 15
        aa = (aa + h(bb, cc, dd) + w[2] + 1859775393) rl 14
        dd = (dd + h(aa, bb, cc) + w[7] + 1859775393) rl 8
        cc = (cc + h(dd, aa, bb) + w[0] + 1859775393) rl 13
        bb = (bb + h(cc, dd, aa) + w[6] + 1859775393) rl 6
        aa = (aa + h(bb, cc, dd) + w[13] + 1859775393) rl 5
        dd = (dd + h(aa, bb, cc) + w[11] + 1859775393) rl 12
        cc = (cc + h(dd, aa, bb) + w[5] + 1859775393) rl 7
        bb = (bb + h(cc, dd, aa) + w[12] + 1859775393) rl 5

        aa = (aa + i(bb, cc, dd) + w[1] + -1894007588) rl 11
        dd = (dd + i(aa, bb, cc) + w[9] + -1894007588) rl 12
        cc = (cc + i(dd, aa, bb) + w[11] + -1894007588) rl 14
        bb = (bb + i(cc, dd, aa) + w[10] + -1894007588) rl 15
        aa = (aa + i(bb, cc, dd) + w[0] + -1894007588) rl 14
        dd = (dd + i(aa, bb, cc) + w[8] + -1894007588) rl 15
        cc = (cc + i(dd, aa, bb) + w[12] + -1894007588) rl 9
        bb = (bb + i(cc, dd, aa) + w[4] + -1894007588) rl 8
        aa = (aa + i(bb, cc, dd) + w[13] + -1894007588) rl 9
        dd = (dd + i(aa, bb, cc) + w[3] + -1894007588) rl 14
        cc = (cc + i(dd, aa, bb) + w[7] + -1894007588) rl 5
        bb = (bb + i(cc, dd, aa) + w[15] + -1894007588) rl 6
        aa = (aa + i(bb, cc, dd) + w[14] + -1894007588) rl 8
        dd = (dd + i(aa, bb, cc) + w[5] + -1894007588) rl 6
        cc = (cc + i(dd, aa, bb) + w[6] + -1894007588) rl 5
        bb = (bb + i(cc, dd, aa) + w[2] + -1894007588) rl 12

        aaa = (aaa + i(bbb, ccc, ddd) + w[5] + 1352829926) rl 8
        ddd = (ddd + i(aaa, bbb, ccc) + w[14] + 1352829926) rl 9
        ccc = (ccc + i(ddd, aaa, bbb) + w[7] + 1352829926) rl 9
        bbb = (bbb + i(ccc, ddd, aaa) + w[0] + 1352829926) rl 11
        aaa = (aaa + i(bbb, ccc, ddd) + w[9] + 1352829926) rl 13
        ddd = (ddd + i(aaa, bbb, ccc) + w[2] + 1352829926) rl 15
        ccc = (ccc + i(ddd, aaa, bbb) + w[11] + 1352829926) rl 15
        bbb = (bbb + i(ccc, ddd, aaa) + w[4] + 1352829926) rl 5
        aaa = (aaa + i(bbb, ccc, ddd) + w[13] + 1352829926) rl 7
        ddd = (ddd + i(aaa, bbb, ccc) + w[6] + 1352829926) rl 7
        ccc = (ccc + i(ddd, aaa, bbb) + w[15] + 1352829926) rl 8
        bbb = (bbb + i(ccc, ddd, aaa) + w[8] + 1352829926) rl 11
        aaa = (aaa + i(bbb, ccc, ddd) + w[1] + 1352829926) rl 14
        ddd = (ddd + i(aaa, bbb, ccc) + w[10] + 1352829926) rl 14
        ccc = (ccc + i(ddd, aaa, bbb) + w[3] + 1352829926) rl 12
        bbb = (bbb + i(ccc, ddd, aaa) + w[12] + 1352829926) rl 6

        aaa = (aaa + h(bbb, ccc, ddd) + w[6] + 1548603684) rl 9
        ddd = (ddd + h(aaa, bbb, ccc) + w[11] + 1548603684) rl 13
        ccc = (ccc + h(ddd, aaa, bbb) + w[3] + 1548603684) rl 15
        bbb = (bbb + h(ccc, ddd, aaa) + w[7] + 1548603684) rl 7
        aaa = (aaa + h(bbb, ccc, ddd) + w[0] + 1548603684) rl 12
        ddd = (ddd + h(aaa, bbb, ccc) + w[13] + 1548603684) rl 8
        ccc = (ccc + h(ddd, aaa, bbb) + w[5] + 1548603684) rl 9
        bbb = (bbb + h(ccc, ddd, aaa) + w[10] + 1548603684) rl 11
        aaa = (aaa + h(bbb, ccc, ddd) + w[14] + 1548603684) rl 7
        ddd = (ddd + h(aaa, bbb, ccc) + w[15] + 1548603684) rl 7
        ccc = (ccc + h(ddd, aaa, bbb) + w[8] + 1548603684) rl 12
        bbb = (bbb + h(ccc, ddd, aaa) + w[12] + 1548603684) rl 7
        aaa = (aaa + h(bbb, ccc, ddd) + w[4] + 1548603684) rl 6
        ddd = (ddd + h(aaa, bbb, ccc) + w[9] + 1548603684) rl 15
        ccc = (ccc + h(ddd, aaa, bbb) + w[1] + 1548603684) rl 13
        bbb = (bbb + h(ccc, ddd, aaa) + w[2] + 1548603684) rl 11

        aaa = (aaa + g(bbb, ccc, ddd) + w[15] + 1836072691) rl 9
        ddd = (ddd + g(aaa, bbb, ccc) + w[5] + 1836072691) rl 7
        ccc = (ccc + g(ddd, aaa, bbb) + w[1] + 1836072691) rl 15
        bbb = (bbb + g(ccc, ddd, aaa) + w[3] + 1836072691) rl 11
        aaa = (aaa + g(bbb, ccc, ddd) + w[7] + 1836072691) rl 8
        ddd = (ddd + g(aaa, bbb, ccc) + w[14] + 1836072691) rl 6
        ccc = (ccc + g(ddd, aaa, bbb) + w[6] + 1836072691) rl 6
        bbb = (bbb + g(ccc, ddd, aaa) + w[9] + 1836072691) rl 14
        aaa = (aaa + g(bbb, ccc, ddd) + w[11] + 1836072691) rl 12
        ddd = (ddd + g(aaa, bbb, ccc) + w[8] + 1836072691) rl 13
        ccc = (ccc + g(ddd, aaa, bbb) + w[12] + 1836072691) rl 5
        bbb = (bbb + g(ccc, ddd, aaa) + w[2] + 1836072691) rl 14
        aaa = (aaa + g(bbb, ccc, ddd) + w[10] + 1836072691) rl 13
        ddd = (ddd + g(aaa, bbb, ccc) + w[0] + 1836072691) rl 13
        ccc = (ccc + g(ddd, aaa, bbb) + w[4] + 1836072691) rl 7
        bbb = (bbb + g(ccc, ddd, aaa) + w[13] + 1836072691) rl 5

        aaa = (aaa + f(bbb, ccc, ddd) + w[8]) rl 15
        ddd = (ddd + f(aaa, bbb, ccc) + w[6]) rl 5
        ccc = (ccc + f(ddd, aaa, bbb) + w[4]) rl 8
        bbb = (bbb + f(ccc, ddd, aaa) + w[1]) rl 11
        aaa = (aaa + f(bbb, ccc, ddd) + w[3]) rl 14
        ddd = (ddd + f(aaa, bbb, ccc) + w[11]) rl 14
        ccc = (ccc + f(ddd, aaa, bbb) + w[15]) rl 6
        bbb = (bbb + f(ccc, ddd, aaa) + w[0]) rl 14
        aaa = (aaa + f(bbb, ccc, ddd) + w[5]) rl 6
        ddd = (ddd + f(aaa, bbb, ccc) + w[12]) rl 9
        ccc = (ccc + f(ddd, aaa, bbb) + w[2]) rl 12
        bbb = (bbb + f(ccc, ddd, aaa) + w[13]) rl 9
        aaa = (aaa + f(bbb, ccc, ddd) + w[9]) rl 12
        ddd = (ddd + f(aaa, bbb, ccc) + w[7]) rl 5
        ccc = (ccc + f(ddd, aaa, bbb) + w[10]) rl 15
        bbb = (bbb + f(ccc, ddd, aaa) + w[14]) rl 8

        ddd += cc + r[1]
        r[1] = r[2] + dd + aaa
        r[2] = r[3] + aa + bbb
        r[3] = r[0] + bb + ccc
        r[0] = ddd

        ms += 512L
    }

    protected override fun transformFinal(
        output: ByteArray,
        offset: Int,
        remaining: ByteArray,
        remainingSize: Int,
    ): Unit {

        val lms = ms + remainingSize.toLong() * 8L

        if (remainingSize > 55) {
            padding.copyInto(remaining, remainingSize, 0, 64 - remainingSize)
            transformBlock(remaining)
            padding.copyInto(remaining, 0, 8, 64)
        } else {
            padding.copyInto(remaining, remainingSize, 0, 56 - remainingSize)
        }

        lms.copyIntoLe(remaining, 56)

        transformBlock(remaining)

        for (i in 0 until 4)
            r[i].copyIntoLe(output, offset + 4 * i)
    }

    protected override fun resetState(): Unit {
        ms = 0L
        cr.copyInto(r)
        cw.copyInto(w)
    }

    private companion object {

        private val cr = intArrayOf(1732584193, -271733879, -1732584194, 271733878)
        private val cw = IntArray(16)
        private val padding = byteArrayOf(
            -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0
        )

        private fun f(x: Int, y: Int, z: Int) = x xor y xor z

        private fun g(x: Int, y: Int, z: Int) = (x and y) or (x.inv() and z)

        private fun h(x: Int, y: Int, z: Int) = (x or y.inv()) xor z

        private fun i(x: Int, y: Int, z: Int) = (x and z) or (y and z.inv())
    }
}
