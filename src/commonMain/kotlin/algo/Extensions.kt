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

//
// ByteArray
//

internal fun ByteArray.beIntAt(index: Int) =
    (this[index].toInt() shl 24) or
        (this[index + 1].toInt() and 255 shl 16) or
        (this[index + 2].toInt() and 255 shl 8) or
        (this[index + 3].toInt() and 255)

internal fun ByteArray.leIntAt(index: Int) =
    (this[index].toInt() and 255) or
        (this[index + 1].toInt() and 255 shl 8) or
        (this[index + 2].toInt() and 255 shl 16) or
        (this[index + 3].toInt() shl 24)

//
// Int
//

internal fun Int.copyIntoBe(buffer: ByteArray, offset: Int) {
    buffer[offset] = this.ushr(24).toByte()
    buffer[offset + 1] = this.ushr(16).toByte()
    buffer[offset + 2] = this.ushr(8).toByte()
    buffer[offset + 3] = this.toByte()
}

internal fun Int.copyIntoLe(buffer: ByteArray, offset: Int) {
    buffer[offset] = this.toByte()
    buffer[offset + 1] = this.ushr(8).toByte()
    buffer[offset + 2] = this.ushr(16).toByte()
    buffer[offset + 3] = this.ushr(24).toByte()
}

internal infix fun Int.rl(count: Int) = (this shl count) or (this ushr (32 - count))

//
// Long
//

internal fun Long.copyIntoBe(buffer: ByteArray, offset: Int) {
    buffer[offset] = this.ushr(56).toByte()
    buffer[offset + 1] = this.ushr(48).toByte()
    buffer[offset + 2] = this.ushr(40).toByte()
    buffer[offset + 3] = this.ushr(32).toByte()
    buffer[offset + 4] = this.ushr(24).toByte()
    buffer[offset + 5] = this.ushr(16).toByte()
    buffer[offset + 6] = this.ushr(8).toByte()
    buffer[offset + 7] = this.toByte()
}

internal fun Long.copyIntoLe(buffer: ByteArray, offset: Int) {
    buffer[offset] = this.toByte()
    buffer[offset + 1] = this.ushr(8).toByte()
    buffer[offset + 2] = this.ushr(16).toByte()
    buffer[offset + 3] = this.ushr(24).toByte()
    buffer[offset + 4] = this.ushr(32).toByte()
    buffer[offset + 5] = this.ushr(40).toByte()
    buffer[offset + 6] = this.ushr(48).toByte()
    buffer[offset + 7] = this.ushr(56).toByte()
}
