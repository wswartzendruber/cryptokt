/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.cryptokt.algo

import kotlin.experimental.xor

/**
 * The BLAKE2b digest algorithm, intended to offer the same functionality as SHA-3 while being
 * significantly faster.
 */
public class Blake2bDigestAlgorithm(
    digestSize: Int = 64,
    key: ByteArray? = null,
) : DigestAlgorithm(128, digestSize) {

    private val k: ByteArray?
    private val kk: Long
    private val nn = digestSize.toLong()
    private var t0 = 0L
    private var t1 = 0L
    private val b = ByteArray(digestSize)
    private val h = LongArray(8)
    private val m = LongArray(16)
    private val s = LongArray(16)
    private val v = LongArray(16)

    init {

        require(nn > 0 && nn < 65) { "digestSize must be between 1 and 64" }

        resetState()

        if (key != null) {
            k = key.copyInto(ByteArray(blockSize))
            kk = key.size.toLong()
            require(kk > 0 && kk < 65) { "key size must be between 0 and 64" }
            transformBlock(k)
        } else {
            k = null
            kk = 0
        }
    }

    protected override fun transformBlock(block: ByteArray): Unit {

        t0 += 128
        if (t0 < 128)
            t1++

        compress(block, false)
    }

    protected override fun transformFinal(
        output: ByteArray,
        offset: Int,
        remaining: ByteArray,
        remainingSize: Int,
    ): Unit {

        for (i in remainingSize until blockSize)
            remaining[i] = 0

        t0 += remainingSize.toLong()
        if (t0 < remainingSize)
            t1++

        compress(remaining, true)

        for (i in 0 until digestSize)
            output[i + offset] = (h[i shr 3] shr (8 * (i and 7)) and 255).toByte()
    }

    protected override fun resetState(): Unit {
        iv.copyInto(h)
        h[0] = h[0] xor 16842752 xor (kk shl 8) xor nn
        t0 = 0L
        t1 = 0L
    }

    private fun compress(block: ByteArray, final: Boolean) {

        h.copyInto(v)
        iv.copyInto(v, 8)
        v[12] = v[12] xor t0
        v[13] = v[13] xor t1
        if (final)
            v[14] = v[14].inv()

        for (i in 0 until 16)
            m[i] = block.leLongAt(4 * i)

        for (i in 0 until 12) {
            g(0, 4, 8, 12, m[sigma[i][0]], m[sigma[i][1]])
            g(1, 5, 9, 13, m[sigma[i][2]], m[sigma[i][3]])
            g(2, 6, 10, 14, m[sigma[i][4]], m[sigma[i][5]])
            g(3, 7, 11, 15, m[sigma[i][6]], m[sigma[i][7]])
            g(0, 5, 10, 15, m[sigma[i][8]], m[sigma[i][9]])
            g(1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]])
            g(2, 7, 8, 13, m[sigma[i][12]], m[sigma[i][13]])
            g(3, 4, 9, 14, m[sigma[i][14]], m[sigma[i][15]])
        }

        for (i in 0 until 8)
            h[i] = h[i] xor v[i] xor v[i + 8]
    }

    private fun g(a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        v[a] = (v[a] + v[b] + x)
        v[d] = (v[d] xor v[a]) rr R1
        v[c] = (v[c] + v[d])
        v[b] = (v[b] xor v[c]) rr R2
        v[a] = (v[a] + v[b] + y)
        v[d] = (v[d] xor v[a]) rr R3
        v[c] = (v[c] + v[d])
        v[b] = (v[b] xor v[c]) rr R4
    }

    private companion object {

        private const val R = 12
        private const val R1 = 32
        private const val R2 = 24
        private const val R3 = 16
        private const val R4 = 63

        private val iv = longArrayOf(
            7640891576956012808, -4942790177534073029, 4354685564936845355,
            -6534734903238641935, 5840696475078001361, -7276294671716946913,
            2270897969802886507, 6620516959819538809,
        )
        private val sigma = arrayOf(
           intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
           intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
           intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
           intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
           intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
           intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
           intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
           intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
           intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
           intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
           intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
           intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        )
    }
}
