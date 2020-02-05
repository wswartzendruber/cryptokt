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

import org.cryptokt.beLongAt
import org.cryptokt.copyIntoBe
import org.cryptokt.forEachSegment
import org.cryptokt.rr

/**
 * The second formally published version of the U.S. Secure Hash Algorithm. This implementation
 * handles SHA2-384, SHA2-512, SHA2-512/224, and SHA2-512/256.
 *
 * @param[size] The digest size for the hash algorithm to output. Valid values are `224`, `256`,
 *     `384`, and `512`.
 */
public class Sha512Hash(size: Int = 512) : Hash() {

    private var mo = 0
    private var ms = 0L
    private val mb = ByteArray(128)
    private val r = LongArray(8)
    private val w = LongArray(80)
    private val cr: LongArray
    private val rc: Int
    private val _length: Int
    private val _size: Int

    init {

        when (size) {
            224 -> {
                cr = cr224
                rc = 3
                _length = 28
                _size = 224
            }
            256 -> {
                cr = cr256
                rc = 3
                _length = 32
                _size = 256
            }
            384 -> {
                cr = cr384
                rc = 5
                _length = 48
                _size = 384
            }
            512 -> {
                cr = cr512
                rc = 7
                _length = 64
                _size = 512
            }
            else -> {
                throw IllegalArgumentException("Valid digest sizes are 224, 256, 384, and 512.")
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

        if (mo > 111) {
            padding.copyInto(mb, mo, 0, 128 - mo)
            transformBlock()
            padding.copyInto(mb, 0, 16, 128)
        } else {
            padding.copyInto(mb, mo, 0, 112 - mo)
        }

        //
        // APPEND LENGTH
        //

        0L.copyIntoBe(mb, 112)
        ms.copyIntoBe(mb, 120)

        //
        // TRANSFORM PADDING + LENGTH
        //

        transformBlock()

        //
        // SET OUTPUT
        //

        for (i in 0..(rc - 1))
            r[i].copyIntoBe(output, 8 * i)

        if (size == 224)
            r[rc].ushr(32).toInt().copyIntoBe(output, 8 * rc)
        else
            r[rc].copyIntoBe(output, 8 * rc)

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
            w[t] = mb.beLongAt(8 * t)

        for (t in 16..79)
            w[t] = ((w[t - 2] rr 19) xor (w[t - 2] rr 61) xor (w[t - 2] ushr 6)) +
                w[t - 7] +
                ((w[t - 15] rr 1) xor (w[t - 15] rr 8) xor (w[t - 15] ushr 7)) +
                w[t - 16]

        var t1: Long
        var t2: Long
        var a = r[0]
        var b = r[1]
        var c = r[2]
        var d = r[3]
        var e = r[4]
        var f = r[5]
        var g = r[6]
        var h = r[7]

        for (t in 0..79) {
            t1 = h + ((e rr 14) xor (e rr 18) xor (e rr 41)) +
                ((e and f) xor (e.inv() and g)) + k[t] + w[t]
            t2 = ((a rr 28) xor (a rr 34) xor (a rr 39)) +
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

        private val cmb = ByteArray(128)
        private val cr224 = longArrayOf(
            -8341449602262348382, 8350123849800275158, 2160240930085379202,
            7466358040605728719, 1111592415079452072, 8638871050018654530,
            4583966954114332360, 1230299281376055969
        )
        private val cr256 = longArrayOf(
            2463787394917988140, -6965556091613846334, 2563595384472711505,
            -7622211418569250115, -7626776825740460061, -4729309413028513390,
            3098927326965381290, 1060366662362279074
        )
        private val cr384 = longArrayOf(
            -3766243637369397544, 7105036623409894663, -7973340178411365097,
            1526699215303891257, 7436329637833083697, -8163818279084223215,
            -2662702644619276377, 5167115440072839076
        )
        private val cr512 = longArrayOf(
            7640891576956012808, -4942790177534073029, 4354685564936845355,
            -6534734903238641935, 5840696475078001361, -7276294671716946913,
            2270897969802886507, 6620516959819538809
        )
        private val cw = LongArray(80)
        private val padding = byteArrayOf(
            -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        )
        private val k = longArrayOf(
            4794697086780616226, 8158064640168781261, -5349999486874862801,
            -1606136188198331460, 4131703408338449720, 6480981068601479193,
            -7908458776815382629, -6116909921290321640, -2880145864133508542,
            1334009975649890238, 2608012711638119052, 6128411473006802146,
            8268148722764581231, -9160688886553864527, -7215885187991268811,
            -4495734319001033068, -1973867731355612462, -1171420211273849373,
            1135362057144423861, 2597628984639134821, 3308224258029322869,
            5365058923640841347, 6679025012923562964, 8573033837759648693,
            -7476448914759557205, -6327057829258317296, -5763719355590565569,
            -4658551843659510044, -4116276920077217854, -3051310485924567259,
            489312712824947311, 1452737877330783856, 2861767655752347644,
            3322285676063803686, 5560940570517711597, 5996557281743188959,
            7280758554555802590, 8532644243296465576, -9096487096722542874,
            -7894198246740708037, -6719396339535248540, -6333637450476146687,
            -4446306890439682159, -4076793802049405392, -3345356375505022440,
            -2983346525034927856, -860691631967231958, 1182934255886127544,
            1847814050463011016, 2177327727835720531, 2830643537854262169,
            3796741975233480872, 4115178125766777443, 5681478168544905931,
            6601373596472566643, 7507060721942968483, 8399075790359081724,
            8693463985226723168, -8878714635349349518, -8302665154208450068,
            -8016688836872298968, -6606660893046293015, -4685533653050689259,
            -4147400797238176981, -3880063495543823972, -3348786107499101689,
            -1523767162380948706, -757361751448694408, 500013540394364858,
            748580250866718886, 1242879168328830382, 1977374033974150939,
            2944078676154940804, 3659926193048069267, 4368137639120453308,
            4836135668995329356, 5532061633213252278, 6448918945643986474,
            6902733635092675308, 7801388544844847127
        )
    }
}
