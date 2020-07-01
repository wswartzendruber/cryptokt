/*
 * Copyright 2020 William Swartzendruber
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a
 * copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package org.cryptokt.algo

import org.cryptokt.copyIntoLe
import org.cryptokt.leIntAt
import org.cryptokt.rl

/**
 * The second formally published version of RIPE's message digest algorithm. This implementation
 * handles RIPEMD-160.
 *
 * @constructor Initializes a new RIPEMD-160 instance with a block size of 512 bits and a digest
 *     size of 160 bits.
 */
public class Ripemd160Hash : Hash(512, 160) {

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

        aa += f(bb, cc, dd) + w[0]
        aa = (aa rl 11) + ee
        cc = cc rl 10
        ee += f(aa, bb, cc) + w[1]
        ee = (ee rl 14) + dd
        bb = bb rl 10
        dd += f(ee, aa, bb) + w[2]
        dd = (dd rl 15) + cc
        aa = aa rl 10
        cc += f(dd, ee, aa) + w[3]
        cc = (cc rl 12) + bb
        ee = ee rl 10
        bb += f(cc, dd, ee) + w[4]
        bb = (bb rl 5) + aa
        dd = dd rl 10
        aa += f(bb, cc, dd) + w[5]
        aa = (aa rl 8) + ee
        cc = cc rl 10
        ee += f(aa, bb, cc) + w[6]
        ee = (ee rl 7) + dd
        bb = bb rl 10
        dd += f(ee, aa, bb) + w[7]
        dd = (dd rl 9) + cc
        aa = aa rl 10
        cc += f(dd, ee, aa) + w[8]
        cc = (cc rl 11) + bb
        ee = ee rl 10
        bb += f(cc, dd, ee) + w[9]
        bb = (bb rl 13) + aa
        dd = dd rl 10
        aa += f(bb, cc, dd) + w[10]
        aa = (aa rl 14) + ee
        cc = cc rl 10
        ee += f(aa, bb, cc) + w[11]
        ee = (ee rl 15) + dd
        bb = bb rl 10
        dd += f(ee, aa, bb) + w[12]
        dd = (dd rl 6) + cc
        aa = aa rl 10
        cc += f(dd, ee, aa) + w[13]
        cc = (cc rl 7) + bb
        ee = ee rl 10
        bb += f(cc, dd, ee) + w[14]
        bb = (bb rl 9) + aa
        dd = dd rl 10
        aa += f(bb, cc, dd) + w[15]
        aa = (aa rl 8) + ee
        cc = cc rl 10

        ee += g(aa, bb, cc) + w[7] + 1518500249
        ee = (ee rl 7) + dd
        bb = bb rl 10
        dd += g(ee, aa, bb) + w[4] + 1518500249
        dd = (dd rl 6) + cc
        aa = aa rl 10
        cc += g(dd, ee, aa) + w[13] + 1518500249
        cc = (cc rl 8) + bb
        ee = ee rl 10
        bb += g(cc, dd, ee) + w[1] + 1518500249
        bb = (bb rl 13) + aa
        dd = dd rl 10
        aa += g(bb, cc, dd) + w[10] + 1518500249
        aa = (aa rl 11) + ee
        cc = cc rl 10
        ee += g(aa, bb, cc) + w[6] + 1518500249
        ee = (ee rl 9) + dd
        bb = bb rl 10
        dd += g(ee, aa, bb) + w[15] + 1518500249
        dd = (dd rl 7) + cc
        aa = aa rl 10
        cc += g(dd, ee, aa) + w[3] + 1518500249
        cc = (cc rl 15) + bb
        ee = ee rl 10
        bb += g(cc, dd, ee) + w[12] + 1518500249
        bb = (bb rl 7) + aa
        dd = dd rl 10
        aa += g(bb, cc, dd) + w[0] + 1518500249
        aa = (aa rl 12) + ee
        cc = cc rl 10
        ee += g(aa, bb, cc) + w[9] + 1518500249
        ee = (ee rl 15) + dd
        bb = bb rl 10
        dd += g(ee, aa, bb) + w[5] + 1518500249
        dd = (dd rl 9) + cc
        aa = aa rl 10
        cc += g(dd, ee, aa) + w[2] + 1518500249
        cc = (cc rl 11) + bb
        ee = ee rl 10
        bb += g(cc, dd, ee) + w[14] + 1518500249
        bb = (bb rl 7) + aa
        dd = dd rl 10
        aa += g(bb, cc, dd) + w[11] + 1518500249
        aa = (aa rl 13) + ee
        cc = cc rl 10
        ee += g(aa, bb, cc) + w[8] + 1518500249
        ee = (ee rl 12) + dd
        bb = bb rl 10

        dd += h(ee, aa, bb) + w[3] + 1859775393
        dd = (dd rl 11) + cc
        aa = aa rl 10
        cc += h(dd, ee, aa) + w[10] + 1859775393
        cc = (cc rl 13) + bb
        ee = ee rl 10
        bb += h(cc, dd, ee) + w[14] + 1859775393
        bb = (bb rl 6) + aa
        dd = dd rl 10
        aa += h(bb, cc, dd) + w[4] + 1859775393
        aa = (aa rl 7) + ee
        cc = cc rl 10
        ee += h(aa, bb, cc) + w[9] + 1859775393
        ee = (ee rl 14) + dd
        bb = bb rl 10
        dd += h(ee, aa, bb) + w[15] + 1859775393
        dd = (dd rl 9) + cc
        aa = aa rl 10
        cc += h(dd, ee, aa) + w[8] + 1859775393
        cc = (cc rl 13) + bb
        ee = ee rl 10
        bb += h(cc, dd, ee) + w[1] + 1859775393
        bb = (bb rl 15) + aa
        dd = dd rl 10
        aa += h(bb, cc, dd) + w[2] + 1859775393
        aa = (aa rl 14) + ee
        cc = cc rl 10
        ee += h(aa, bb, cc) + w[7] + 1859775393
        ee = (ee rl 8) + dd
        bb = bb rl 10
        dd += h(ee, aa, bb) + w[0] + 1859775393
        dd = (dd rl 13) + cc
        aa = aa rl 10
        cc += h(dd, ee, aa) + w[6] + 1859775393
        cc = (cc rl 6) + bb
        ee = ee rl 10
        bb += h(cc, dd, ee) + w[13] + 1859775393
        bb = (bb rl 5) + aa
        dd = dd rl 10
        aa += h(bb, cc, dd) + w[11] + 1859775393
        aa = (aa rl 12) + ee
        cc = cc rl 10
        ee += h(aa, bb, cc) + w[5] + 1859775393
        ee = (ee rl 7) + dd
        bb = bb rl 10
        dd += h(ee, aa, bb) + w[12] + 1859775393
        dd = (dd rl 5) + cc
        aa = aa rl 10

        cc += i(dd, ee, aa) + w[1] + -1894007588
        cc = (cc rl 11) + bb
        ee = ee rl 10
        bb += i(cc, dd, ee) + w[9] + -1894007588
        bb = (bb rl 12) + aa
        dd = dd rl 10
        aa += i(bb, cc, dd) + w[11] + -1894007588
        aa = (aa rl 14) + ee
        cc = cc rl 10
        ee += i(aa, bb, cc) + w[10] + -1894007588
        ee = (ee rl 15) + dd
        bb = bb rl 10
        dd += i(ee, aa, bb) + w[0] + -1894007588
        dd = (dd rl 14) + cc
        aa = aa rl 10
        cc += i(dd, ee, aa) + w[8] + -1894007588
        cc = (cc rl 15) + bb
        ee = ee rl 10
        bb += i(cc, dd, ee) + w[12] + -1894007588
        bb = (bb rl 9) + aa
        dd = dd rl 10
        aa += i(bb, cc, dd) + w[4] + -1894007588
        aa = (aa rl 8) + ee
        cc = cc rl 10
        ee += i(aa, bb, cc) + w[13] + -1894007588
        ee = (ee rl 9) + dd
        bb = bb rl 10
        dd += i(ee, aa, bb) + w[3] + -1894007588
        dd = (dd rl 14) + cc
        aa = aa rl 10
        cc += i(dd, ee, aa) + w[7] + -1894007588
        cc = (cc rl 5) + bb
        ee = ee rl 10
        bb += i(cc, dd, ee) + w[15] + -1894007588
        bb = (bb rl 6) + aa
        dd = dd rl 10
        aa += i(bb, cc, dd) + w[14] + -1894007588
        aa = (aa rl 8) + ee
        cc = cc rl 10
        ee += i(aa, bb, cc) + w[5] + -1894007588
        ee = (ee rl 6) + dd
        bb = bb rl 10
        dd += i(ee, aa, bb) + w[6] + -1894007588
        dd = (dd rl 5) + cc
        aa = aa rl 10
        cc += i(dd, ee, aa) + w[2] + -1894007588
        cc = (cc rl 12) + bb
        ee = ee rl 10

        bb += j(cc, dd, ee) + w[4] + -1454113458
        bb = (bb rl 9) + aa
        dd = dd rl 10
        aa += j(bb, cc, dd) + w[0] + -1454113458
        aa = (aa rl 15) + ee
        cc = cc rl 10
        ee += j(aa, bb, cc) + w[5] + -1454113458
        ee = (ee rl 5) + dd
        bb = bb rl 10
        dd += j(ee, aa, bb) + w[9] + -1454113458
        dd = (dd rl 11) + cc
        aa = aa rl 10
        cc += j(dd, ee, aa) + w[7] + -1454113458
        cc = (cc rl 6) + bb
        ee = ee rl 10
        bb += j(cc, dd, ee) + w[12] + -1454113458
        bb = (bb rl 8) + aa
        dd = dd rl 10
        aa += j(bb, cc, dd) + w[2] + -1454113458
        aa = (aa rl 13) + ee
        cc = cc rl 10
        ee += j(aa, bb, cc) + w[10] + -1454113458
        ee = (ee rl 12) + dd
        bb = bb rl 10
        dd += j(ee, aa, bb) + w[14] + -1454113458
        dd = (dd rl 5) + cc
        aa = aa rl 10
        cc += j(dd, ee, aa) + w[1] + -1454113458
        cc = (cc rl 12) + bb
        ee = ee rl 10
        bb += j(cc, dd, ee) + w[3] + -1454113458
        bb = (bb rl 13) + aa
        dd = dd rl 10
        aa += j(bb, cc, dd) + w[8] + -1454113458
        aa = (aa rl 14) + ee
        cc = cc rl 10
        ee += j(aa, bb, cc) + w[11] + -1454113458
        ee = (ee rl 11) + dd
        bb = bb rl 10
        dd += j(ee, aa, bb) + w[6] + -1454113458
        dd = (dd rl 8) + cc
        aa = aa rl 10
        cc += j(dd, ee, aa) + w[15] + -1454113458
        cc = (cc rl 5) + bb
        ee = ee rl 10
        bb += j(cc, dd, ee) + w[13] + -1454113458
        bb = (bb rl 6) + aa
        dd = dd rl 10

        aaa += j(bbb, ccc, ddd) + w[5] + 1352829926
        aaa = (aaa rl 8) + eee
        ccc = ccc rl 10
        eee += j(aaa, bbb, ccc) + w[14] + 1352829926
        eee = (eee rl 9) + ddd
        bbb = bbb rl 10
        ddd += j(eee, aaa, bbb) + w[7] + 1352829926
        ddd = (ddd rl 9) + ccc
        aaa = aaa rl 10
        ccc += j(ddd, eee, aaa) + w[0] + 1352829926
        ccc = (ccc rl 11) + bbb
        eee = eee rl 10
        bbb += j(ccc, ddd, eee) + w[9] + 1352829926
        bbb = (bbb rl 13) + aaa
        ddd = ddd rl 10
        aaa += j(bbb, ccc, ddd) + w[2] + 1352829926
        aaa = (aaa rl 15) + eee
        ccc = ccc rl 10
        eee += j(aaa, bbb, ccc) + w[11] + 1352829926
        eee = (eee rl 15) + ddd
        bbb = bbb rl 10
        ddd += j(eee, aaa, bbb) + w[4] + 1352829926
        ddd = (ddd rl 5) + ccc
        aaa = aaa rl 10
        ccc += j(ddd, eee, aaa) + w[13] + 1352829926
        ccc = (ccc rl 7) + bbb
        eee = eee rl 10
        bbb += j(ccc, ddd, eee) + w[6] + 1352829926
        bbb = (bbb rl 7) + aaa
        ddd = ddd rl 10
        aaa += j(bbb, ccc, ddd) + w[15] + 1352829926
        aaa = (aaa rl 8) + eee
        ccc = ccc rl 10
        eee += j(aaa, bbb, ccc) + w[8] + 1352829926
        eee = (eee rl 11) + ddd
        bbb = bbb rl 10
        ddd += j(eee, aaa, bbb) + w[1] + 1352829926
        ddd = (ddd rl 14) + ccc
        aaa = aaa rl 10
        ccc += j(ddd, eee, aaa) + w[10] + 1352829926
        ccc = (ccc rl 14) + bbb
        eee = eee rl 10
        bbb += j(ccc, ddd, eee) + w[3] + 1352829926
        bbb = (bbb rl 12) + aaa
        ddd = ddd rl 10
        aaa += j(bbb, ccc, ddd) + w[12] + 1352829926
        aaa = (aaa rl 6) + eee
        ccc = ccc rl 10

        eee += i(aaa, bbb, ccc) + w[6] + 1548603684
        eee = (eee rl 9) + ddd
        bbb = bbb rl 10
        ddd += i(eee, aaa, bbb) + w[11] + 1548603684
        ddd = (ddd rl 13) + ccc
        aaa = aaa rl 10
        ccc += i(ddd, eee, aaa) + w[3] + 1548603684
        ccc = (ccc rl 15) + bbb
        eee = eee rl 10
        bbb += i(ccc, ddd, eee) + w[7] + 1548603684
        bbb = (bbb rl 7) + aaa
        ddd = ddd rl 10
        aaa += i(bbb, ccc, ddd) + w[0] + 1548603684
        aaa = (aaa rl 12) + eee
        ccc = ccc rl 10
        eee += i(aaa, bbb, ccc) + w[13] + 1548603684
        eee = (eee rl 8) + ddd
        bbb = bbb rl 10
        ddd += i(eee, aaa, bbb) + w[5] + 1548603684
        ddd = (ddd rl 9) + ccc
        aaa = aaa rl 10
        ccc += i(ddd, eee, aaa) + w[10] + 1548603684
        ccc = (ccc rl 11) + bbb
        eee = eee rl 10
        bbb += i(ccc, ddd, eee) + w[14] + 1548603684
        bbb = (bbb rl 7) + aaa
        ddd = ddd rl 10
        aaa += i(bbb, ccc, ddd) + w[15] + 1548603684
        aaa = (aaa rl 7) + eee
        ccc = ccc rl 10
        eee += i(aaa, bbb, ccc) + w[8] + 1548603684
        eee = (eee rl 12) + ddd
        bbb = bbb rl 10
        ddd += i(eee, aaa, bbb) + w[12] + 1548603684
        ddd = (ddd rl 7) + ccc
        aaa = aaa rl 10
        ccc += i(ddd, eee, aaa) + w[4] + 1548603684
        ccc = (ccc rl 6) + bbb
        eee = eee rl 10
        bbb += i(ccc, ddd, eee) + w[9] + 1548603684
        bbb = (bbb rl 15) + aaa
        ddd = ddd rl 10
        aaa += i(bbb, ccc, ddd) + w[1] + 1548603684
        aaa = (aaa rl 13) + eee
        ccc = ccc rl 10
        eee += i(aaa, bbb, ccc) + w[2] + 1548603684
        eee = (eee rl 11) + ddd
        bbb = bbb rl 10

        ddd += h(eee, aaa, bbb) + w[15] + 1836072691
        ddd = (ddd rl 9) + ccc
        aaa = aaa rl 10
        ccc += h(ddd, eee, aaa) + w[5] + 1836072691
        ccc = (ccc rl 7) + bbb
        eee = eee rl 10
        bbb += h(ccc, ddd, eee) + w[1] + 1836072691
        bbb = (bbb rl 15) + aaa
        ddd = ddd rl 10
        aaa += h(bbb, ccc, ddd) + w[3] + 1836072691
        aaa = (aaa rl 11) + eee
        ccc = ccc rl 10
        eee += h(aaa, bbb, ccc) + w[7] + 1836072691
        eee = (eee rl 8) + ddd
        bbb = bbb rl 10
        ddd += h(eee, aaa, bbb) + w[14] + 1836072691
        ddd = (ddd rl 6) + ccc
        aaa = aaa rl 10
        ccc += h(ddd, eee, aaa) + w[6] + 1836072691
        ccc = (ccc rl 6) + bbb
        eee = eee rl 10
        bbb += h(ccc, ddd, eee) + w[9] + 1836072691
        bbb = (bbb rl 14) + aaa
        ddd = ddd rl 10
        aaa += h(bbb, ccc, ddd) + w[11] + 1836072691
        aaa = (aaa rl 12) + eee
        ccc = ccc rl 10
        eee += h(aaa, bbb, ccc) + w[8] + 1836072691
        eee = (eee rl 13) + ddd
        bbb = bbb rl 10
        ddd += h(eee, aaa, bbb) + w[12] + 1836072691
        ddd = (ddd rl 5) + ccc
        aaa = aaa rl 10
        ccc += h(ddd, eee, aaa) + w[2] + 1836072691
        ccc = (ccc rl 14) + bbb
        eee = eee rl 10
        bbb += h(ccc, ddd, eee) + w[10] + 1836072691
        bbb = (bbb rl 13) + aaa
        ddd = ddd rl 10
        aaa += h(bbb, ccc, ddd) + w[0] + 1836072691
        aaa = (aaa rl 13) + eee
        ccc = ccc rl 10
        eee += h(aaa, bbb, ccc) + w[4] + 1836072691
        eee = (eee rl 7) + ddd
        bbb = bbb rl 10
        ddd += h(eee, aaa, bbb) + w[13] + 1836072691
        ddd = (ddd rl 5) + ccc
        aaa = aaa rl 10

        ccc += g(ddd, eee, aaa) + w[8] + 2053994217
        ccc = (ccc rl 15) + bbb
        eee = eee rl 10
        bbb += g(ccc, ddd, eee) + w[6] + 2053994217
        bbb = (bbb rl 5) + aaa
        ddd = ddd rl 10
        aaa += g(bbb, ccc, ddd) + w[4] + 2053994217
        aaa = (aaa rl 8) + eee
        ccc = ccc rl 10
        eee += g(aaa, bbb, ccc) + w[1] + 2053994217
        eee = (eee rl 11) + ddd
        bbb = bbb rl 10
        ddd += g(eee, aaa, bbb) + w[3] + 2053994217
        ddd = (ddd rl 14) + ccc
        aaa = aaa rl 10
        ccc += g(ddd, eee, aaa) + w[11] + 2053994217
        ccc = (ccc rl 14) + bbb
        eee = eee rl 10
        bbb += g(ccc, ddd, eee) + w[15] + 2053994217
        bbb = (bbb rl 6) + aaa
        ddd = ddd rl 10
        aaa += g(bbb, ccc, ddd) + w[0] + 2053994217
        aaa = (aaa rl 14) + eee
        ccc = ccc rl 10
        eee += g(aaa, bbb, ccc) + w[5] + 2053994217
        eee = (eee rl 6) + ddd
        bbb = bbb rl 10
        ddd += g(eee, aaa, bbb) + w[12] + 2053994217
        ddd = (ddd rl 9) + ccc
        aaa = aaa rl 10
        ccc += g(ddd, eee, aaa) + w[2] + 2053994217
        ccc = (ccc rl 12) + bbb
        eee = eee rl 10
        bbb += g(ccc, ddd, eee) + w[13] + 2053994217
        bbb = (bbb rl 9) + aaa
        ddd = ddd rl 10
        aaa += g(bbb, ccc, ddd) + w[9] + 2053994217
        aaa = (aaa rl 12) + eee
        ccc = ccc rl 10
        eee += g(aaa, bbb, ccc) + w[7] + 2053994217
        eee = (eee rl 5) + ddd
        bbb = bbb rl 10
        ddd += g(eee, aaa, bbb) + w[10] + 2053994217
        ddd = (ddd rl 15) + ccc
        aaa = aaa rl 10
        ccc += g(ddd, eee, aaa) + w[14] + 2053994217
        ccc = (ccc rl 8) + bbb
        eee = eee rl 10

        bbb += f(ccc, ddd, eee) + w[12]
        bbb = (bbb rl 8) + aaa
        ddd = ddd rl 10
        aaa += f(bbb, ccc, ddd) + w[15]
        aaa = (aaa rl 5) + eee
        ccc = ccc rl 10
        eee += f(aaa, bbb, ccc) + w[10]
        eee = (eee rl 12) + ddd
        bbb = bbb rl 10
        ddd += f(eee, aaa, bbb) + w[4]
        ddd = (ddd rl 9) + ccc
        aaa = aaa rl 10
        ccc += f(ddd, eee, aaa) + w[1]
        ccc = (ccc rl 12) + bbb
        eee = eee rl 10
        bbb += f(ccc, ddd, eee) + w[5]
        bbb = (bbb rl 5) + aaa
        ddd = ddd rl 10
        aaa += f(bbb, ccc, ddd) + w[8]
        aaa = (aaa rl 14) + eee
        ccc = ccc rl 10
        eee += f(aaa, bbb, ccc) + w[7]
        eee = (eee rl 6) + ddd
        bbb = bbb rl 10
        ddd += f(eee, aaa, bbb) + w[6]
        ddd = (ddd rl 8) + ccc
        aaa = aaa rl 10
        ccc += f(ddd, eee, aaa) + w[2]
        ccc = (ccc rl 13) + bbb
        eee = eee rl 10
        bbb += f(ccc, ddd, eee) + w[13]
        bbb = (bbb rl 6) + aaa
        ddd = ddd rl 10
        aaa += f(bbb, ccc, ddd) + w[14]
        aaa = (aaa rl 5) + eee
        ccc = ccc rl 10
        eee += f(aaa, bbb, ccc) + w[0]
        eee = (eee rl 15) + ddd
        bbb = bbb rl 10
        ddd += f(eee, aaa, bbb) + w[3]
        ddd = (ddd rl 13) + ccc
        aaa = aaa rl 10
        ccc += f(ddd, eee, aaa) + w[9]
        ccc = (ccc rl 11) + bbb
        eee = eee rl 10
        bbb += f(ccc, ddd, eee) + w[11]
        bbb = (bbb rl 11) + aaa
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
        remainingSize: Int
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
