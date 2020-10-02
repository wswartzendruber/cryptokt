/*
 * Copyright 2020 William Swartzendruber
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */

package org.cryptokt.algo

/**
 * Represents the possible digest sizes for SHA2-256.
 *
 * @property[value] The digest size in bits.
 */
public enum class Sha256DigestSize(public val value: Int) {
    /** SHA2-224 */
    _224(224),
    /** SHA2-256 */
    _256(256),
}

/**
 * The second formally published version of the U.S. Secure Hash Algorithm. This implementation
 * handles SHA2-224 and SHA2-256.
 *
 * @constructor Initializes a new SHA2-256 instance with a block size of 512 bits and a
 *     configurable digest size.
 */
public class Sha256DigestAlgorithm(
    private val size: Sha256DigestSize = Sha256DigestSize._256
) : DigestAlgorithm(512, size.value) {

    private var ms = 0L
    private val r = cr[size]!!.copyInto(IntArray(8))
    private val w = cw.copyInto(IntArray(64))
    private val rc =
        when (size) {
            Sha256DigestSize._224 -> 7
            Sha256DigestSize._256 -> 8
        }

    protected override fun transformBlock(block: ByteArray): Unit {

        for (t in 0 until 16)
            w[t] = block.beIntAt(4 * t)

        for (t in 16 until 64)
            w[t] = ((w[t - 2] rr 17) xor (w[t - 2] rr 19) xor (w[t - 2] ushr 10)) +
                w[t - 7] +
                ((w[t - 15] rr 7) xor (w[t - 15] rr 18) xor (w[t - 15] ushr 3)) +
                w[t - 16]

        var t1: Int
        var t2: Int
        var a = r[0]
        var b = r[1]
        var c = r[2]
        var d = r[3]
        var e = r[4]
        var f = r[5]
        var g = r[6]
        var h = r[7]

        for (t in 0 until 64) {
            t1 = h + ((e rr 6) xor (e rr 11) xor (e rr 25)) +
                ((e and f) xor (e.inv() and g)) + k[t] + w[t]
            t2 = ((a rr 2) xor (a rr 13) xor (a rr 22)) +
                ((a and b) xor (a and c) xor (b and c))
            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2
        }

        r[0] += a
        r[1] += b
        r[2] += c
        r[3] += d
        r[4] += e
        r[5] += f
        r[6] += g
        r[7] += h

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

        lms.copyIntoBe(remaining, 56)

        transformBlock(remaining)

        for (i in 0 until rc)
            r[i].copyIntoBe(output, 4 * i)
    }

    protected override fun resetState(): Unit {
        ms = 0L
        cr[size]!!.copyInto(r)
        cw.copyInto(w)
    }

    private companion object {

        private val cr = mapOf(
            Sha256DigestSize._224 to intArrayOf(
                -1056596264, 914150663, 812702999, -150054599, -4191439, 1750603025, 1694076839,
                -1090891868
            ),
            Sha256DigestSize._256 to intArrayOf(
                1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372,
                528734635, 1541459225
            ),
        )
        private val cw = IntArray(64)
        private val padding = byteArrayOf(
            -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0
        )
        private val k = intArrayOf(
            1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993, -1841331548,
            -1424204075, -670586216, 310598401, 607225278, 1426881987, 1925078388, -2132889090,
            -1680079193, -1046744716, -459576895, -272742522, 264347078, 604807628, 770255983,
            1249150122, 1555081692, 1996064986, -1740746414, -1473132947, -1341970488,
            -1084653625, -958395405, -710438585, 113926993, 338241895, 666307205, 773529912,
            1294757372, 1396182291, 1695183700, 1986661051, -2117940946, -1838011259,
            -1564481375, -1474664885, -1035236496, -949202525, -778901479, -694614492,
            -200395387, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571,
            1322822218, 1537002063, 1747873779, 1955562222, 2024104815, -2067236844,
            -1933114872, -1866530822, -1538233109, -1090935817, -965641998
        )
    }
}
