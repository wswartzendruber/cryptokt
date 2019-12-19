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

@ExperimentalUnsignedTypes
internal inline fun forEachSegment(
    destination: UByteArray,
    destinationOffset: Int,
    source: ByteArray,
    sourceOffset: Int,
    length: Int,
    block: () -> Unit
): Int {

    val ls = source.asUByteArray()
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

@ExperimentalUnsignedTypes
internal fun UByteArray.clear() {
    for (index in this.indices)
        this[index] = 0U
}

@ExperimentalUnsignedTypes
internal operator fun UByteArray.set(indices: IntRange, value: UByte) {
    for (i in indices)
        this[i] = value
}

@ExperimentalUnsignedTypes
internal fun UInt.reverseByteOrder() =
    (this and 0x000000FFU shl 24) or
    (this and 0x0000FF00U shl 8) or
    (this and 0x00FF0000U shr 8) or
    (this and 0xFF000000U shr 24)

@ExperimentalUnsignedTypes
internal fun UInt.ubyteAt(index: Int) =
    when (index) {
        0 -> this.and(0xFF000000U).shr(24).and(0xFFU).toUByte()
        1 -> this.and(0x00FF0000U).shr(16).and(0xFFU).toUByte()
        2 -> this.and(0x0000FF00U).shr(8).and(0xFFU).toUByte()
        3 -> this.and(0x000000FFU).toUByte()
        else -> throw IllegalArgumentException("UByte index must be 0-7.")
    }

@ExperimentalUnsignedTypes
internal fun ULong.ubyteAt(index: Int) =
    when (index) {
        0 -> this.and(0xFF00000000000000U).shr(56).and(0xFFU).toUByte()
        1 -> this.and(0x00FF000000000000U).shr(48).and(0xFFU).toUByte()
        2 -> this.and(0x0000FF0000000000U).shr(40).and(0xFFU).toUByte()
        3 -> this.and(0x000000FF00000000U).shr(32).and(0xFFU).toUByte()
        4 -> this.and(0x00000000FF000000U).shr(24).and(0xFFU).toUByte()
        5 -> this.and(0x0000000000FF0000U).shr(16).and(0xFFU).toUByte()
        6 -> this.and(0x000000000000FF00U).shr(8).and(0xFFU).toUByte()
        7 -> this.and(0x00000000000000FFU).toUByte()
        else -> throw IllegalArgumentException("UByte index must be 0-7.")
    }
