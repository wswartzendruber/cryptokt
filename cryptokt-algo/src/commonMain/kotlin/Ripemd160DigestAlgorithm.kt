/*
 * Copyright 2020 William Swartzendruber
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a
 * copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package org.cryptokt.algo

/**
 * The second formally published version of RIPE's message digest algorithm. This implementation
 * handles RIPEMD-160.
 *
 * @constructor Initializes a new RIPEMD-160 instance with a block size of 512 bits and a digest
 *     size of 160 bits.
 */
public class Ripemd160DigestAlgorithm : DigestAlgorithm(512, 160) {

    private var ms = 0L
    private val r = cr.copyInto(IntArray(5))
    private val w = cw.copyInto(IntArray(16))

    protected override fun transformBlock(block: ByteArray): Unit {

        //
        // READ BLOCK
        //

        for (i in 0..15)
            w[i] = block.leIntAt(4 * i)

        var aa = r[0]
        var bb = r[1]
        var cc = r[2]
        var dd = r[3]
        var ee = r[4]
        var aaa = r[0]
        var bbb = r[1]
        var ccc = r[2]
        var ddd = r[3]
        var eee = r[4]

        aa = ((aa + f(bb, cc, dd) + w[0]) rl 11) + ee
        cc = cc rl 10
        ee = ((ee + f(aa, bb, cc) + w[1]) rl 14) + dd
        bb = bb rl 10
        dd = ((dd + f(ee, aa, bb) + w[2]) rl 15) + cc
        aa = aa rl 10
        cc = ((cc + f(dd, ee, aa) + w[3]) rl 12) + bb
        ee = ee rl 10
        bb = ((bb + f(cc, dd, ee) + w[4]) rl 5) + aa
        dd = dd rl 10
        aa = ((aa + f(bb, cc, dd) + w[5]) rl 8) + ee
        cc = cc rl 10
        ee = ((ee + f(aa, bb, cc) + w[6]) rl 7) + dd
        bb = bb rl 10
        dd = ((dd + f(ee, aa, bb) + w[7]) rl 9) + cc
        aa = aa rl 10
        cc = ((cc + f(dd, ee, aa) + w[8]) rl 11) + bb
        ee = ee rl 10
        bb = ((bb + f(cc, dd, ee) + w[9]) rl 13) + aa
        dd = dd rl 10
        aa = ((aa + f(bb, cc, dd) + w[10]) rl 14) + ee
        cc = cc rl 10
        ee = ((ee + f(aa, bb, cc) + w[11]) rl 15) + dd
        bb = bb rl 10
        dd = ((dd + f(ee, aa, bb) + w[12]) rl 6) + cc
        aa = aa rl 10
        cc = ((cc + f(dd, ee, aa) + w[13]) rl 7) + bb
        ee = ee rl 10
        bb = ((bb + f(cc, dd, ee) + w[14]) rl 9) + aa
        dd = dd rl 10
        aa = ((aa + f(bb, cc, dd) + w[15]) rl 8) + ee
        cc = cc rl 10

        ee = ((ee + g(aa, bb, cc) + w[7] + 1518500249) rl 7) + dd
        bb = bb rl 10
        dd = ((dd + g(ee, aa, bb) + w[4] + 1518500249) rl 6) + cc
        aa = aa rl 10
        cc = ((cc + g(dd, ee, aa) + w[13] + 1518500249) rl 8) + bb
        ee = ee rl 10
        bb = ((bb + g(cc, dd, ee) + w[1] + 1518500249) rl 13) + aa
        dd = dd rl 10
        aa = ((aa + g(bb, cc, dd) + w[10] + 1518500249) rl 11) + ee
        cc = cc rl 10
        ee = ((ee + g(aa, bb, cc) + w[6] + 1518500249) rl 9) + dd
        bb = bb rl 10
        dd = ((dd + g(ee, aa, bb) + w[15] + 1518500249) rl 7) + cc
        aa = aa rl 10
        cc = ((cc + g(dd, ee, aa) + w[3] + 1518500249) rl 15) + bb
        ee = ee rl 10
        bb = ((bb + g(cc, dd, ee) + w[12] + 1518500249) rl 7) + aa
        dd = dd rl 10
        aa = ((aa + g(bb, cc, dd) + w[0] + 1518500249) rl 12) + ee
        cc = cc rl 10
        ee = ((ee + g(aa, bb, cc) + w[9] + 1518500249) rl 15) + dd
        bb = bb rl 10
        dd = ((dd + g(ee, aa, bb) + w[5] + 1518500249) rl 9) + cc
        aa = aa rl 10
        cc = ((cc + g(dd, ee, aa) + w[2] + 1518500249) rl 11) + bb
        ee = ee rl 10
        bb = ((bb + g(cc, dd, ee) + w[14] + 1518500249) rl 7) + aa
        dd = dd rl 10
        aa = ((aa + g(bb, cc, dd) + w[11] + 1518500249) rl 13) + ee
        cc = cc rl 10
        ee = ((ee + g(aa, bb, cc) + w[8] + 1518500249) rl 12) + dd
        bb = bb rl 10

        dd = ((dd + h(ee, aa, bb) + w[3] + 1859775393) rl 11) + cc
        aa = aa rl 10
        cc = ((cc + h(dd, ee, aa) + w[10] + 1859775393) rl 13) + bb
        ee = ee rl 10
        bb = ((bb + h(cc, dd, ee) + w[14] + 1859775393) rl 6) + aa
        dd = dd rl 10
        aa = ((aa + h(bb, cc, dd) + w[4] + 1859775393) rl 7) + ee
        cc = cc rl 10
        ee = ((ee + h(aa, bb, cc) + w[9] + 1859775393) rl 14) + dd
        bb = bb rl 10
        dd = ((dd + h(ee, aa, bb) + w[15] + 1859775393) rl 9) + cc
        aa = aa rl 10
        cc = ((cc + h(dd, ee, aa) + w[8] + 1859775393) rl 13) + bb
        ee = ee rl 10
        bb = ((bb + h(cc, dd, ee) + w[1] + 1859775393) rl 15) + aa
        dd = dd rl 10
        aa = ((aa + h(bb, cc, dd) + w[2] + 1859775393) rl 14) + ee
        cc = cc rl 10
        ee = ((ee + h(aa, bb, cc) + w[7] + 1859775393) rl 8) + dd
        bb = bb rl 10
        dd = ((dd + h(ee, aa, bb) + w[0] + 1859775393) rl 13) + cc
        aa = aa rl 10
        cc = ((cc + h(dd, ee, aa) + w[6] + 1859775393) rl 6) + bb
        ee = ee rl 10
        bb = ((bb + h(cc, dd, ee) + w[13] + 1859775393) rl 5) + aa
        dd = dd rl 10
        aa = ((aa + h(bb, cc, dd) + w[11] + 1859775393) rl 12) + ee
        cc = cc rl 10
        ee = ((ee + h(aa, bb, cc) + w[5] + 1859775393) rl 7) + dd
        bb = bb rl 10
        dd = ((dd + h(ee, aa, bb) + w[12] + 1859775393) rl 5) + cc
        aa = aa rl 10

        cc = ((cc + i(dd, ee, aa) + w[1] + -1894007588) rl 11) + bb
        ee = ee rl 10
        bb = ((bb + i(cc, dd, ee) + w[9] + -1894007588) rl 12) + aa
        dd = dd rl 10
        aa = ((aa + i(bb, cc, dd) + w[11] + -1894007588) rl 14) + ee
        cc = cc rl 10
        ee = ((ee + i(aa, bb, cc) + w[10] + -1894007588) rl 15) + dd
        bb = bb rl 10
        dd = ((dd + i(ee, aa, bb) + w[0] + -1894007588) rl 14) + cc
        aa = aa rl 10
        cc = ((cc + i(dd, ee, aa) + w[8] + -1894007588) rl 15) + bb
        ee = ee rl 10
        bb = ((bb + i(cc, dd, ee) + w[12] + -1894007588) rl 9) + aa
        dd = dd rl 10
        aa = ((aa + i(bb, cc, dd) + w[4] + -1894007588) rl 8) + ee
        cc = cc rl 10
        ee = ((ee + i(aa, bb, cc) + w[13] + -1894007588) rl 9) + dd
        bb = bb rl 10
        dd = ((dd + i(ee, aa, bb) + w[3] + -1894007588) rl 14) + cc
        aa = aa rl 10
        cc = ((cc + i(dd, ee, aa) + w[7] + -1894007588) rl 5) + bb
        ee = ee rl 10
        bb = ((bb + i(cc, dd, ee) + w[15] + -1894007588) rl 6) + aa
        dd = dd rl 10
        aa = ((aa + i(bb, cc, dd) + w[14] + -1894007588) rl 8) + ee
        cc = cc rl 10
        ee = ((ee + i(aa, bb, cc) + w[5] + -1894007588) rl 6) + dd
        bb = bb rl 10
        dd = ((dd + i(ee, aa, bb) + w[6] + -1894007588) rl 5) + cc
        aa = aa rl 10
        cc = ((cc + i(dd, ee, aa) + w[2] + -1894007588) rl 12) + bb
        ee = ee rl 10

        bb = ((bb + j(cc, dd, ee) + w[4] + -1454113458) rl 9) + aa
        dd = dd rl 10
        aa = ((aa + j(bb, cc, dd) + w[0] + -1454113458) rl 15) + ee
        cc = cc rl 10
        ee = ((ee + j(aa, bb, cc) + w[5] + -1454113458) rl 5) + dd
        bb = bb rl 10
        dd = ((dd + j(ee, aa, bb) + w[9] + -1454113458) rl 11) + cc
        aa = aa rl 10
        cc = ((cc + j(dd, ee, aa) + w[7] + -1454113458) rl 6) + bb
        ee = ee rl 10
        bb = ((bb + j(cc, dd, ee) + w[12] + -1454113458) rl 8) + aa
        dd = dd rl 10
        aa = ((aa + j(bb, cc, dd) + w[2] + -1454113458) rl 13) + ee
        cc = cc rl 10
        ee = ((ee + j(aa, bb, cc) + w[10] + -1454113458) rl 12) + dd
        bb = bb rl 10
        dd = ((dd + j(ee, aa, bb) + w[14] + -1454113458) rl 5) + cc
        aa = aa rl 10
        cc = ((cc + j(dd, ee, aa) + w[1] + -1454113458) rl 12) + bb
        ee = ee rl 10
        bb = ((bb + j(cc, dd, ee) + w[3] + -1454113458) rl 13) + aa
        dd = dd rl 10
        aa = ((aa + j(bb, cc, dd) + w[8] + -1454113458) rl 14) + ee
        cc = cc rl 10
        ee = ((ee + j(aa, bb, cc) + w[11] + -1454113458) rl 11) + dd
        bb = bb rl 10
        dd = ((dd + j(ee, aa, bb) + w[6] + -1454113458) rl 8) + cc
        aa = aa rl 10
        cc = ((cc + j(dd, ee, aa) + w[15] + -1454113458) rl 5) + bb
        ee = ee rl 10
        bb = ((bb + j(cc, dd, ee) + w[13] + -1454113458) rl 6) + aa
        dd = dd rl 10

        aaa = ((aaa + j(bbb, ccc, ddd) + w[5] + 1352829926) rl 8) + eee
        ccc = ccc rl 10
        eee = ((eee + j(aaa, bbb, ccc) + w[14] + 1352829926) rl 9) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + j(eee, aaa, bbb) + w[7] + 1352829926) rl 9) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + j(ddd, eee, aaa) + w[0] + 1352829926) rl 11) + bbb
        eee = eee rl 10
        bbb = ((bbb + j(ccc, ddd, eee) + w[9] + 1352829926) rl 13) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + j(bbb, ccc, ddd) + w[2] + 1352829926) rl 15) + eee
        ccc = ccc rl 10
        eee = ((eee + j(aaa, bbb, ccc) + w[11] + 1352829926) rl 15) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + j(eee, aaa, bbb) + w[4] + 1352829926) rl 5) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + j(ddd, eee, aaa) + w[13] + 1352829926) rl 7) + bbb
        eee = eee rl 10
        bbb = ((bbb + j(ccc, ddd, eee) + w[6] + 1352829926) rl 7) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + j(bbb, ccc, ddd) + w[15] + 1352829926) rl 8) + eee
        ccc = ccc rl 10
        eee = ((eee + j(aaa, bbb, ccc) + w[8] + 1352829926) rl 11) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + j(eee, aaa, bbb) + w[1] + 1352829926) rl 14) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + j(ddd, eee, aaa) + w[10] + 1352829926) rl 14) + bbb
        eee = eee rl 10
        bbb = ((bbb + j(ccc, ddd, eee) + w[3] + 1352829926) rl 12) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + j(bbb, ccc, ddd) + w[12] + 1352829926) rl 6) + eee
        ccc = ccc rl 10

        eee = ((eee + i(aaa, bbb, ccc) + w[6] + 1548603684) rl 9) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + i(eee, aaa, bbb) + w[11] + 1548603684) rl 13) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + i(ddd, eee, aaa) + w[3] + 1548603684) rl 15) + bbb
        eee = eee rl 10
        bbb = ((bbb + i(ccc, ddd, eee) + w[7] + 1548603684) rl 7) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + i(bbb, ccc, ddd) + w[0] + 1548603684) rl 12) + eee
        ccc = ccc rl 10
        eee = ((eee + i(aaa, bbb, ccc) + w[13] + 1548603684) rl 8) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + i(eee, aaa, bbb) + w[5] + 1548603684) rl 9) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + i(ddd, eee, aaa) + w[10] + 1548603684) rl 11) + bbb
        eee = eee rl 10
        bbb = ((bbb + i(ccc, ddd, eee) + w[14] + 1548603684) rl 7) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + i(bbb, ccc, ddd) + w[15] + 1548603684) rl 7) + eee
        ccc = ccc rl 10
        eee = ((eee + i(aaa, bbb, ccc) + w[8] + 1548603684) rl 12) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + i(eee, aaa, bbb) + w[12] + 1548603684) rl 7) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + i(ddd, eee, aaa) + w[4] + 1548603684) rl 6) + bbb
        eee = eee rl 10
        bbb = ((bbb + i(ccc, ddd, eee) + w[9] + 1548603684) rl 15) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + i(bbb, ccc, ddd) + w[1] + 1548603684) rl 13) + eee
        ccc = ccc rl 10
        eee = ((eee + i(aaa, bbb, ccc) + w[2] + 1548603684) rl 11) + ddd
        bbb = bbb rl 10

        ddd = ((ddd + h(eee, aaa, bbb) + w[15] + 1836072691) rl 9) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + h(ddd, eee, aaa) + w[5] + 1836072691) rl 7) + bbb
        eee = eee rl 10
        bbb = ((bbb + h(ccc, ddd, eee) + w[1] + 1836072691) rl 15) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + h(bbb, ccc, ddd) + w[3] + 1836072691) rl 11) + eee
        ccc = ccc rl 10
        eee = ((eee + h(aaa, bbb, ccc) + w[7] + 1836072691) rl 8) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + h(eee, aaa, bbb) + w[14] + 1836072691) rl 6) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + h(ddd, eee, aaa) + w[6] + 1836072691) rl 6) + bbb
        eee = eee rl 10
        bbb = ((bbb + h(ccc, ddd, eee) + w[9] + 1836072691) rl 14) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + h(bbb, ccc, ddd) + w[11] + 1836072691) rl 12) + eee
        ccc = ccc rl 10
        eee = ((eee + h(aaa, bbb, ccc) + w[8] + 1836072691) rl 13) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + h(eee, aaa, bbb) + w[12] + 1836072691) rl 5) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + h(ddd, eee, aaa) + w[2] + 1836072691) rl 14) + bbb
        eee = eee rl 10
        bbb = ((bbb + h(ccc, ddd, eee) + w[10] + 1836072691) rl 13) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + h(bbb, ccc, ddd) + w[0] + 1836072691) rl 13) + eee
        ccc = ccc rl 10
        eee = ((eee + h(aaa, bbb, ccc) + w[4] + 1836072691) rl 7) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + h(eee, aaa, bbb) + w[13] + 1836072691) rl 5) + ccc
        aaa = aaa rl 10

        ccc = ((ccc + g(ddd, eee, aaa) + w[8] + 2053994217) rl 15) + bbb
        eee = eee rl 10
        bbb = ((bbb + g(ccc, ddd, eee) + w[6] + 2053994217) rl 5) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + g(bbb, ccc, ddd) + w[4] + 2053994217) rl 8) + eee
        ccc = ccc rl 10
        eee = ((eee + g(aaa, bbb, ccc) + w[1] + 2053994217) rl 11) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + g(eee, aaa, bbb) + w[3] + 2053994217) rl 14) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + g(ddd, eee, aaa) + w[11] + 2053994217) rl 14) + bbb
        eee = eee rl 10
        bbb = ((bbb + g(ccc, ddd, eee) + w[15] + 2053994217) rl 6) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + g(bbb, ccc, ddd) + w[0] + 2053994217) rl 14) + eee
        ccc = ccc rl 10
        eee = ((eee + g(aaa, bbb, ccc) + w[5] + 2053994217) rl 6) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + g(eee, aaa, bbb) + w[12] + 2053994217) rl 9) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + g(ddd, eee, aaa) + w[2] + 2053994217) rl 12) + bbb
        eee = eee rl 10
        bbb = ((bbb + g(ccc, ddd, eee) + w[13] + 2053994217) rl 9) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + g(bbb, ccc, ddd) + w[9] + 2053994217) rl 12) + eee
        ccc = ccc rl 10
        eee = ((eee + g(aaa, bbb, ccc) + w[7] + 2053994217) rl 5) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + g(eee, aaa, bbb) + w[10] + 2053994217) rl 15) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + g(ddd, eee, aaa) + w[14] + 2053994217) rl 8) + bbb
        eee = eee rl 10

        bbb = ((bbb + f(ccc, ddd, eee) + w[12]) rl 8) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + f(bbb, ccc, ddd) + w[15]) rl 5) + eee
        ccc = ccc rl 10
        eee = ((eee + f(aaa, bbb, ccc) + w[10]) rl 12) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + f(eee, aaa, bbb) + w[4]) rl 9) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + f(ddd, eee, aaa) + w[1]) rl 12) + bbb
        eee = eee rl 10
        bbb = ((bbb + f(ccc, ddd, eee) + w[5]) rl 5) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + f(bbb, ccc, ddd) + w[8]) rl 14) + eee
        ccc = ccc rl 10
        eee = ((eee + f(aaa, bbb, ccc) + w[7]) rl 6) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + f(eee, aaa, bbb) + w[6]) rl 8) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + f(ddd, eee, aaa) + w[2]) rl 13) + bbb
        eee = eee rl 10
        bbb = ((bbb + f(ccc, ddd, eee) + w[13]) rl 6) + aaa
        ddd = ddd rl 10
        aaa = ((aaa + f(bbb, ccc, ddd) + w[14]) rl 5) + eee
        ccc = ccc rl 10
        eee = ((eee + f(aaa, bbb, ccc) + w[0]) rl 15) + ddd
        bbb = bbb rl 10
        ddd = ((ddd + f(eee, aaa, bbb) + w[3]) rl 13) + ccc
        aaa = aaa rl 10
        ccc = ((ccc + f(ddd, eee, aaa) + w[9]) rl 11) + bbb
        eee = eee rl 10
        bbb = ((bbb + f(ccc, ddd, eee) + w[11]) rl 11) + aaa
        ddd = ddd rl 10

        ddd += cc + r[1]
        r[1] = r[2] + dd + eee
        r[2] = r[3] + ee + aaa
        r[3] = r[4] + aa + bbb
        r[4] = r[0] + bb + ccc
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

        for (i in 0..4)
            r[i].copyIntoLe(output, 4 * i)
    }

    protected override fun resetState(): Unit {
        ms = 0L
        cr.copyInto(r)
        cw.copyInto(w)
    }

    private companion object {

        private val cr = intArrayOf(1732584193, -271733879, -1732584194, 271733878, -1009589776)
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

        private fun j(x: Int, y: Int, z: Int) = x xor (y or z.inv())
    }
}
