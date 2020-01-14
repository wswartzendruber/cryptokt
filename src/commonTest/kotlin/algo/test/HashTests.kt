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

import kotlin.random.Random
import kotlin.test.assertTrue
import kotlin.test.Test

import org.cryptokt.algo.Md2Hash
import org.cryptokt.algo.Md4Hash
import org.cryptokt.algo.Md5Hash
import org.cryptokt.algo.Sha1Hash
import org.cryptokt.algo.Sha256Hash

class HashTests {

    @Test
    fun `MD2 accuracy`() {

        val md2 = Md2Hash()

        for (hashValue in md2HashValues) {
            md2.input(hashValue.key.toAsciiByteArray())
            assertTrue(md2.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `MD2 performance (1 GB)`() {

        val md2 = Md2Hash()

        for (i in 0..(1024 * 1024))
            md2.input(randomData)

        md2.digest()
    }

    @Test
    fun `MD4 accurancy`() {

        val md4 = Md4Hash()

        for (hashValue in md4HashValues) {
            md4.input(hashValue.key.toAsciiByteArray())
            assertTrue(md4.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `MD4 performance (1 GB)`() {

        val md4 = Md4Hash()

        for (i in 0..(1024 * 1024))
            md4.input(randomData)

        md4.digest()
    }

    @Test
    fun `MD5 accuracy`() {

        val md5 = Md5Hash()

        for (hashValue in md5HashValues) {
            md5.input(hashValue.key.toAsciiByteArray())
            assertTrue(md5.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `MD5 performance (1 GB)`() {

        val md5 = Md5Hash()

        for (i in 0..(1024 * 1024))
            md5.input(randomData)

        md5.digest()
    }

    @Test
    fun `SHA1 accuracy`() {

        val sha1 = Sha1Hash()

        for (hashValue in sha1HashValues) {
            sha1.input(hashValue.key.toAsciiByteArray())
            assertTrue(sha1.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `SHA1 performance (1 GB)`() {

        val sha1 = Sha1Hash()

        for (i in 0..(1024 * 1024))
            sha1.input(randomData)

        sha1.digest()
    }

    @Test
    fun `SHA2-256 accuracy`() {

        val sha256 = Sha256Hash()

        for (hashValue in sha2256HashValues) {
            sha256.input(hashValue.key.toAsciiByteArray())
            assertTrue(sha256.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `SHA2-256 performance (1 GB)`() {

        val sha256 = Sha256Hash()

        for (i in 0..(1024 * 1024))
            sha256.input(randomData)

        sha256.digest()
    }

    @Test
    fun `SHA2-224 accuracy`() {

        val sha256 = Sha256Hash(224)

        for (hashValue in sha2224HashValues) {
            sha256.input(hashValue.key.toAsciiByteArray())
            assertTrue(sha256.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `SHA2-224 performance (1 GB)`() {

        val sha256 = Sha256Hash(224)

        for (i in 0..(1024 * 1024))
            sha256.input(randomData)

        sha256.digest()
    }

    companion object {

        val randomData = Random.nextBytes(ByteArray(1024))

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
            "" to "d41d8cd98f00b204e9800998ecf8427e"/*,
            "a" to "0cc175b9c0f1b6a831c399e269772661",
            "abc" to "900150983cd24fb0d6963f7d28e17f72",
            "message digest" to "f96b697d7cb7938d525a2f31aaf161d0",
            "abcdefghijklmnopqrstuvwxyz" to "c3fcd3d76192e4007dfb496cca67e13b",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "d174ab98d277d9f5a5611c2c9f419d9f",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "57edf4a22be3c955ac49da2e2107b67a"*/
        )

        val sha1HashValues = mapOf(
            "" to "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "a" to "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
            "abc" to "a9993e364706816aba3e25717850c26c9cd0d89d",
            "message digest" to "c12252ceda8be8994d5fa0290a47231c1d16aae3",
            "abcdefghijklmnopqrstuvwxyz" to "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "761c457bf73b14d27e9e9265c46f4b4dda11f940",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "50abf5706a150990a08b2c5ea40fa0e585554732"
        )

        val sha2224HashValues = mapOf(
            "" to "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            "a" to "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
            "abc" to "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            "message digest" to "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb",
            "abcdefghijklmnopqrstuvwxyz" to "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e"
        )

        val sha2256HashValues = mapOf(
            "" to "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "a" to "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            "abc" to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "message digest" to "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
            "abcdefghijklmnopqrstuvwxyz" to "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"
        )
    }
}
