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
 * The second formally published version of the U.S. Secure Hash Algorithm. This implementation
 * handles SHA2-384, SHA2-512, SHA2-512/224, and SHA2-512/256.
 *
 * @constructor Initializes a new SHA2-512 instance with a block size of 1,024 bits and a
 *     configurable digest size.
 */
public class Sha512DigestAlgorithm(
    private val size: Sha512DigestSize = Sha512DigestSize._512
) : DigestAlgorithm(128, size.digestSize) {

    private var ms = 0L
    private val r = size.cr.copyInto(LongArray(8))
    private val w = cw.copyInto(LongArray(80))

    protected override fun transformBlock(block: ByteArray): Unit {

        for (t in 0 until 16)
            w[t] = block.beLongAt(8 * t)

        for (t in 16 until 80)
            w[t] = f(w[t - 2] rr 19, w[t - 2] rr 61, w[t - 2] ushr 6) + w[t - 7] +
                f(w[t - 15] rr 1, w[t - 15] rr 8, w[t - 15] ushr 7) + w[t - 16]

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

        for (t in 0 until 80) {
            t1 = h + f(e rr 14, e rr 18, e rr 41) + (e and f xor (e.inv() and g)) + k[t] + w[t]
            t2 = f(a rr 28, a rr 34, a rr 39) + f(a and b, a and c, b and c)
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

        if (remainingSize > 111) {
            padding.copyInto(remaining, remainingSize, 0, 128 - remainingSize)
            transformBlock(remaining)
            padding.copyInto(remaining, 0, 16, 128)
        } else {
            padding.copyInto(remaining, remainingSize, 0, 112 - remainingSize)
        }

        0L.copyIntoBe(remaining, 112)
        lms.copyIntoBe(remaining, 120)

        transformBlock(remaining)

        for (i in 0 until size.rc)
            r[i].copyIntoBe(output, offset + 8 * i)

        if (digestSize == 28)
            r[size.rc].ushr(32).toInt().copyIntoBe(output, offset + 8 * size.rc)
        else
            r[size.rc].copyIntoBe(output, offset + 8 * size.rc)
    }

    protected override fun resetState(): Unit {
        ms = 0L
        size.cr.copyInto(r)
        cw.copyInto(w)
    }

    private companion object {

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

        private fun f(x: Long, y: Long, z: Long) = x xor y xor z
    }
}
