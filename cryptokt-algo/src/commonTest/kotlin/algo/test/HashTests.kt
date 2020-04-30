/*
 * Copyright 2020 William Swartzendruber
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
import org.cryptokt.algo.Sha256DigestSize
import org.cryptokt.algo.Sha512Hash
import org.cryptokt.algo.Sha512DigestSize

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
    fun `MD4 accurancy`() {

        val md4 = Md4Hash()

        for (hashValue in md4HashValues) {
            md4.input(hashValue.key.toAsciiByteArray())
            assertTrue(md4.digest().toHexString() == hashValue.value)
        }
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
    fun `SHA1 accuracy`() {

        val sha1 = Sha1Hash()

        for (hashValue in sha1HashValues) {
            sha1.input(hashValue.key.toAsciiByteArray())
            assertTrue(sha1.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `SHA2-256 accuracy`() {

        val sha256 = Sha256Hash(Sha256DigestSize._256)

        for (hashValue in sha2256HashValues) {
            sha256.input(hashValue.key.toAsciiByteArray())
            assertTrue(sha256.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `SHA2-224 accuracy`() {

        val sha256 = Sha256Hash(Sha256DigestSize._224)

        for (hashValue in sha2224HashValues) {
            sha256.input(hashValue.key.toAsciiByteArray())
            assertTrue(sha256.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `SHA2-512 accuracy`() {

        val sha512 = Sha512Hash(Sha512DigestSize._512)

        for (hashValue in sha2512HashValues) {
            sha512.input(hashValue.key.toAsciiByteArray())
            assertTrue(sha512.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `SHA2-384 accuracy`() {

        val sha2384 = Sha512Hash(Sha512DigestSize._384)

        for (hashValue in sha2384HashValues) {
            sha2384.input(hashValue.key.toAsciiByteArray())
            assertTrue(sha2384.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `SHA2-512-224 accuracy`() {

        val sha2512224 = Sha512Hash(Sha512DigestSize._224)

        for (hashValue in sha2512224HashValues) {
            sha2512224.input(hashValue.key.toAsciiByteArray())
            assertTrue(sha2512224.digest().toHexString() == hashValue.value)
        }
    }

    @Test
    fun `SHA2-512-256 accuracy`() {

        val sha2512256 = Sha512Hash(Sha512DigestSize._256)

        for (hashValue in sha2512256HashValues) {
            sha2512256.input(hashValue.key.toAsciiByteArray())
            assertTrue(sha2512256.digest().toHexString() == hashValue.value)
        }
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
            "" to "d41d8cd98f00b204e9800998ecf8427e",
            "a" to "0cc175b9c0f1b6a831c399e269772661",
            "abc" to "900150983cd24fb0d6963f7d28e17f72",
            "message digest" to "f96b697d7cb7938d525a2f31aaf161d0",
            "abcdefghijklmnopqrstuvwxyz" to "c3fcd3d76192e4007dfb496cca67e13b",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "d174ab98d277d9f5a5611c2c9f419d9f",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "57edf4a22be3c955ac49da2e2107b67a"
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

        val sha2256HashValues = mapOf(
            "" to "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "a" to "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            "abc" to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "message digest" to "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
            "abcdefghijklmnopqrstuvwxyz" to "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"
        )

        val sha2224HashValues = mapOf(
            "" to "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        )

        val sha2512HashValues = mapOf(
            "" to "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "a" to "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
            "abc" to "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "message digest" to "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
            "abcdefghijklmnopqrstuvwxyz" to "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
            "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" to "0d9a7df5b6a6ad20da519effda888a7344b6c0c7adcc8e2d504b4af27aaaacd4e7111c713f71769539629463cb58c86136c521b0414a3c0edf7dc6349c6edaf3"
        )

        val sha2384HashValues = mapOf(
            "" to "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        )

        val sha2512224HashValues = mapOf(
            "" to "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
        )

        val sha2512256HashValues = mapOf(
            "" to "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
        )
    }
}