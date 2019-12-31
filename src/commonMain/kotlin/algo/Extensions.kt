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

internal fun ByteArray.beIntAt(index: Int) =
    this[index + 3].toInt().and(255) or
    (this[index + 2].toInt().and(255) shl 8) or
    (this[index + 1].toInt().and(255) shl 16) or
    (this[index + 0].toInt().and(255) shl 24)

@ExperimentalUnsignedTypes
internal fun UByteArray.beUIntAt(index: Int) =
    this[index + 3].toUInt() or
    (this[index + 2].toUInt() shl 8) or
    (this[index + 1].toUInt() shl 16) or
    (this[index + 0].toUInt() shl 24)

@ExperimentalUnsignedTypes
internal fun UByteArray.leUIntAt(index: Int) =
    this[index].toUInt() or
    (this[index + 1].toUInt() shl 8) or
    (this[index + 2].toUInt() shl 16) or
    (this[index + 3].toUInt() shl 24)

internal operator fun ByteArray.set(indices: IntRange, value: Byte) {
    for (i in indices)
        this[i] = value
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

internal fun Int.byteAt(index: Int) =
    when (index) {
        0 -> this.and(-16777216).shr(24).and(255).toByte()
        1 -> this.and(16711680).shr(16).and(255).toByte()
        2 -> this.and(65280).shr(8).and(255).toByte()
        3 -> this.and(255).toByte()
        else -> throw IllegalArgumentException("Byte index must be 0-3.")
    }

internal infix fun Int.rl(count: Int) =
    (this shl count) or (this shr 1 and 2147483647 shr (31 - count))

@ExperimentalUnsignedTypes
internal fun UInt.ubyteAt(index: Int) =
    when (index) {
        0 -> this.and(0xFF000000U).shr(24).and(0xFFU).toUByte()
        1 -> this.and(0x00FF0000U).shr(16).and(0xFFU).toUByte()
        2 -> this.and(0x0000FF00U).shr(8).and(0xFFU).toUByte()
        3 -> this.and(0x000000FFU).toUByte()
        else -> throw IllegalArgumentException("UByte index must be 0-3.")
    }

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
