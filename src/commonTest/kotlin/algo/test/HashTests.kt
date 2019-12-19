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

import org.cryptokt.algo.Md2Hash
import org.cryptokt.algo.Md4Hash
import org.cryptokt.algo.Md5Hash

class HashTests {

    @Test
    @ExperimentalUnsignedTypes
    fun `MD2 hash`() {

        val md2 = Md2Hash()

        for (hashValue in md2HashValues) {
            md2.input(hashValue.key.toAsciiByteArray())
            assertTrue(md2.digest().toHexString() == hashValue.value)
            md2.reset()
        }
    }

    @Test
    @ExperimentalStdlibApi
    @ExperimentalUnsignedTypes
    fun `MD4 hash`() {

        val md4 = Md4Hash()

        for (hashValue in md4HashValues) {
            md4.input(hashValue.key.toAsciiByteArray())
            assertTrue(md4.digest().toHexString() == hashValue.value)
            md4.reset()
        }
    }

    @Test
    @ExperimentalStdlibApi
    @ExperimentalUnsignedTypes
    fun `MD5 hash`() {

        val md5 = Md5Hash()

        for (hashValue in md5HashValues) {
            md5.input(hashValue.key.toAsciiByteArray())
            assertTrue(md5.digest().toHexString() == hashValue.value)
            md5.reset()
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

        val md4HashValues = mapOf(
            "" to "31d6cfe0d16ae931b73c59d7e0c089c0",
            "a" to "bde52cb31de33e46245e05fbdbd6fb24",
            "abc" to "a448017aaf21d8525fc10ae87aa6729d",
            "message digest" to "d9130a8164549fe818874806e1c7014b",
            "abcdefghijklmnopqrstuvwxyz" to "d79e1c308aa5bbcdeea8ed63df412da9",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "043f8582f241db351ce627e153e7f0e4",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "e33b4ddc9c38f2199c3e7b164fcc0536"
        )

        val md5HashValues = mapOf(
            "" to "d41d8cd98f00b204e9800998ecf8427e",
            "a" to "0cc175b9c0f1b6a831c399e269772661",
            "abc" to "900150983cd24fb0d6963f7d28e17f72",
            "message digest" to "f96b697d7cb7938d525a2f31aaf161d0",
            "abcdefghijklmnopqrstuvwxyz" to "c3fcd3d76192e4007dfb496cca67e13b",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "d174ab98d277d9f5a5611c2c9f419d9f",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "57edf4a22be3c955ac49da2e2107b67a"
        )
    }
}
