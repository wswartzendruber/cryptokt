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
import org.cryptokt.copyIntoBe
import org.cryptokt.forEachSegment
import org.cryptokt.rr

/**
 * The second formally published version of the U.S. Secure Hash Algorithm. This implementation
 * handles SHA2-224 and SHA2-256.
 *
 * @param[size] The digest size for the hash algorithm to output. Valid values are `224` and
 *     `256`.
 */
public class Sha256Hash(size: Int = 256) : Hash() {

    private var mo = 0
    private var ms = 0L
    private val mb = ByteArray(64)
    private val r = IntArray(8)
    private val w = IntArray(64)
    private val cr: IntArray
    private val rc: Int
    private val _length: Int
    private val _size: Int

    init {

        when (size) {
            224 -> {
                cr = cr224
                rc = 6
                _length = 28
                _size = 224
            }
            256 -> {
                cr = cr256
                rc = 7
                _length = 32
                _size = 256
            }
            else -> {
                throw IllegalArgumentException("Valid digest sizes are 224 and 256.")
            }
        }

        reset()
    }

    public override fun input(buffer: ByteArray, offset: Int, length: Int): Unit {
        mo = forEachSegment(
            mb, mo,
            buffer, offset, length,
            {
                transformBlock()
            }
        )
        ms += (length * 8).toLong()
    }

    public override fun digest(output: ByteArray, offset: Int): ByteArray {

        //
        // APPEND PADDING
        //

        if (mo > 55) {
            padding.copyInto(mb, mo, 0, 64 - mo)
            transformBlock()
            padding.copyInto(mb, 0, 8, 64)
        } else {
            padding.copyInto(mb, mo, 0, 56 - mo)
        }

        //
        // APPEND LENGTH
        //

        ms.copyIntoBe(mb, 56)

        //
        // TRANSFORM PADDING + LENGTH
        //

        transformBlock()

        //
        // SET OUTPUT
        //

        for (i in 0..rc)
            r[i].copyIntoBe(output, 4 * i)

        reset()

        return output
    }

    public override fun reset(): Unit {
        mo = 0
        ms = 0L
        cmb.copyInto(mb)
        cr.copyInto(r)
        cw.copyInto(w)
    }

    private fun transformBlock() {

        for (t in 0..15)
            w[t] = mb.beIntAt(4 * t)

        for (t in 16..63)
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

        for (t in 0..63) {
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
    }

    public override val length: Int = _length

    public override val size: Int = _size

    private companion object {

        private val cmb = ByteArray(64)
        private val cr224 = intArrayOf(
            -1056596264, 914150663, 812702999, -150054599, -4191439, 1750603025, 1694076839,
            -1090891868
        )
        private val cr256 = intArrayOf(
            1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372,
            528734635, 1541459225
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
