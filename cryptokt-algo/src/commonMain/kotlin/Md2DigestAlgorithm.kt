/*
 * Copyright 2020 William Swartzendruber
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a
 * copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package org.cryptokt.algo

import kotlin.experimental.xor

/**
 * The first in the MD series by Ronald Rivest. It has been considered broken since 2004.
 *
 * @constructor Initializes a new MD2 instance with a block size and digest size of 128 bits.
 */
public class Md2DigestAlgorithm : DigestAlgorithm(128, 128) {

    private var cl: Byte = 0
    private val cb = ccb.copyInto(ByteArray(16))
    private val xb = cxb.copyInto(ByteArray(48))

    protected override fun transformBlock(block: ByteArray): Unit {

        for (j in 0..15) {
            xb[16 + j] = block[j]
            xb[32 + j] = xb[16 + j] xor xb[j]
        }

        var t = 0

        for (j in 0..17) {
            for (k in 0..47) {
                xb[k] = xb[k] xor s[t]
                t = xb[k].toInt().and(255)
            }
            t = (t + j) % 256
        }

        cb[0] = s[(block[0] xor cl).toInt() and 255] xor cb[0]

        for (i in 1..15)
            cb[i] = s[(block[i] xor cb[i - 1]).toInt() and 255] xor cb[i]

        cl = cb[15]
    }

    protected override fun transformFinal(
        output: ByteArray,
        offset: Int,
        remaining: ByteArray,
        remainingSize: Int,
    ): Unit {

        val paddingValue = (16 - remainingSize).toByte()

        for (i in remainingSize..15)
            remaining[i] = paddingValue

        transformBlock(remaining)
        transformBlock(cb)

        xb.copyInto(output, offset, 0, 16)
    }

    protected override fun resetState(): Unit {
        cl = 0
        ccb.copyInto(cb)
        cxb.copyInto(xb)
    }

    private companion object {

        private val ccb = ByteArray(16)
        private val cxb = ByteArray(48)
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
