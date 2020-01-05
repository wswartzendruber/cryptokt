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

package org.cryptokt

internal inline fun forEachSegment(
    destination: ByteArray,
    destinationOffset: Int,
    source: ByteArray,
    sourceOffset: Int,
    length: Int,
    block: () -> Unit
): Int {

    val ls = source
    var ldo = destinationOffset
    var lso = sourceOffset
    var ll = length

    while (ll > 0) {

        val size = minOf(ll, destination.size - ldo)

        ls.copyInto(destination, ldo, lso, lso + size)
        lso += size
        ldo += size
        ll -= size

        if (ldo == destination.size) {
            ldo = 0
            block()
        }
    }

    return ldo
}

internal fun ByteArray.beIntAt(index: Int) =
    this[index + 3].toInt().and(255) or
    (this[index + 2].toInt().and(255) shl 8) or
    (this[index + 1].toInt().and(255) shl 16) or
    (this[index + 0].toInt().and(255) shl 24)

internal fun Int.byteAt(index: Int) =
    when (index) {
        0 -> this.and(-16777216).shr(24).and(255).toByte()
        1 -> this.and(16711680).shr(16).and(255).toByte()
        2 -> this.and(65280).shr(8).and(255).toByte()
        3 -> this.and(255).toByte()
        else -> throw IllegalArgumentException("Byte index must be 0-3.")
    }

internal infix fun Int.rl(count: Int) = (this shl count) or (this ushr (32 - count))

internal fun Long.byteAt(index: Int) =
    when (index) {
        0 -> this.and(-72057594037927936).shr(56).and(255).toByte()
        1 -> this.and(71776119061217280).shr(48).and(255).toByte()
        2 -> this.and(280375465082880).shr(40).and(255).toByte()
        3 -> this.and(1095216660480).shr(32).and(255).toByte()
        4 -> this.and(4278190080).shr(24).and(255).toByte()
        5 -> this.and(16711680).shr(16).and(255).toByte()
        6 -> this.and(65280).shr(8).and(255).toByte()
        7 -> this.and(255).toByte()
        else -> throw IllegalArgumentException("Byte index must be 0-7.")
    }
