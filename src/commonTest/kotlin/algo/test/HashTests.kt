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

package org.cryptokt.algo.test

import kotlin.test.assertTrue
import kotlin.test.Test

import org.cryptokt.algo.Md2

class HashTests {

    @Test
    fun `MD2`() {

        val md2 = Md2()

        for (hashValue in md2HashValues) {
            md2.input(hashValue.key.toAsciiByteArray())
            assertTrue(md2.digest().toHexString() == hashValue.value)
            md2.reset()
        }
    }

    companion object {

        val md2HashValues = mapOf(
            "" to "8350e5a3e24c153df2275c9f80692773",
            "a" to "32ec01ec4a6dac72c0ab96fb34c0b5d1",
            "abc" to "da853b0d3f88d99b30283a69e6ded6bb",
            "message digest" to "ab4f496bfb2a530b219ff33031fe06b0",
            "abcdefghijklmnopqrstuvwxyz" to "4e8ddff3650292ab5a4108c3aa47940b",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "da33def2a42df13975352846c30338cd",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "d5976f79d83d3a0dc9806c3c66f3efd8"
        )
    }
}
