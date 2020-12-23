/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

import kotlin.random.Random
import kotlin.test.assertTrue
import kotlin.test.Test

import org.cryptokt.algo.DigestAlgorithm
import org.cryptokt.algo.Md2DigestAlgorithm
import org.cryptokt.algo.Md4DigestAlgorithm
import org.cryptokt.algo.Md5DigestAlgorithm
import org.cryptokt.algo.Ripemd128DigestAlgorithm
import org.cryptokt.algo.Ripemd160DigestAlgorithm
import org.cryptokt.algo.Sha1DigestAlgorithm
import org.cryptokt.algo.Sha256DigestAlgorithm
import org.cryptokt.algo.Sha256DigestSize
import org.cryptokt.algo.Sha512DigestAlgorithm
import org.cryptokt.algo.Sha512DigestSize

class DigestAlgorithmTests {

    @Test
    fun MD2_accuracy() {
        testDigestAlgorithmAccuracy(
            Md2DigestAlgorithm(), md2Digests
        )
    }

    @Test
    fun MD2_offsets() {
        testDigestAlgorithmOffsets(
            Md2DigestAlgorithm(), "8350e5a3e24c153df2275c9f80692773".toByteArrayFromHex()
        )
    }

    @Test
    fun MD4_accuracy() {
        testDigestAlgorithmAccuracy(
            Md4DigestAlgorithm(), md4Digests
        )
    }

    @Test
    fun MD5_accuracy() {
        testDigestAlgorithmAccuracy(
            Md5DigestAlgorithm(), md5Digests
        )
    }

    @Test
    fun SHA1_accuracy() {
        testDigestAlgorithmAccuracy(
            Sha1DigestAlgorithm(), sha1Digests
        )
    }

    @Test
    fun SHA2_256_accuracy() {
        testDigestAlgorithmAccuracy(
            Sha256DigestAlgorithm(), sha2256Digests
        )
    }

    @Test
    fun SHA2_224_accuracy() {
        testDigestAlgorithmAccuracy(
            Sha256DigestAlgorithm(Sha256DigestSize._224), sha2224Digests
        )
    }

    @Test
    fun SHA2_512_accuracy() {
        testDigestAlgorithmAccuracy(
            Sha512DigestAlgorithm(), sha2512Digests
        )
    }

    @Test
    fun SHA2_384_accuracy() {
        testDigestAlgorithmAccuracy(
            Sha512DigestAlgorithm(Sha512DigestSize._384), sha2384Digests
        )
    }

    @Test
    fun SHA2_512_224_accuracy() {
        testDigestAlgorithmAccuracy(
            Sha512DigestAlgorithm(Sha512DigestSize._224), sha2512224Digests
        )
    }

    @Test
    fun SHA2_512_256_accuracy() {
        testDigestAlgorithmAccuracy(
            Sha512DigestAlgorithm(Sha512DigestSize._256), sha2512256Digests
        )
    }

    @Test
    fun RIPEMD_128_accuracy() {
        testDigestAlgorithmAccuracy(
            Ripemd128DigestAlgorithm(), ripemd128Digests
        )
    }

    @Test
    fun RIPEMD_160_accuracy() {
        testDigestAlgorithmAccuracy(
            Ripemd160DigestAlgorithm(), ripemd160Digests
        )
    }

    companion object {

        val md2Digests = mapOf(
            "" to "8350e5a3e24c153df2275c9f80692773",
            "a" to "32ec01ec4a6dac72c0ab96fb34c0b5d1",
            "abc" to "da853b0d3f88d99b30283a69e6ded6bb",
            "message digest" to "ab4f496bfb2a530b219ff33031fe06b0",
            "abcdefghijklmnopqrstuvwxyz" to "4e8ddff3650292ab5a4108c3aa47940b",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "da33def2a42df13975352846c30338cd",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "d5976f79d83d3a0dc9806c3c66f3efd8",
        )

        val md4Digests = mapOf(
            "" to "31d6cfe0d16ae931b73c59d7e0c089c0",
            "a" to "bde52cb31de33e46245e05fbdbd6fb24",
            "abc" to "a448017aaf21d8525fc10ae87aa6729d",
            "message digest" to "d9130a8164549fe818874806e1c7014b",
            "abcdefghijklmnopqrstuvwxyz" to "d79e1c308aa5bbcdeea8ed63df412da9",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "043f8582f241db351ce627e153e7f0e4",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "e33b4ddc9c38f2199c3e7b164fcc0536",
        )

        val md5Digests = mapOf(
            "" to "d41d8cd98f00b204e9800998ecf8427e",
            "a" to "0cc175b9c0f1b6a831c399e269772661",
            "abc" to "900150983cd24fb0d6963f7d28e17f72",
            "message digest" to "f96b697d7cb7938d525a2f31aaf161d0",
            "abcdefghijklmnopqrstuvwxyz" to "c3fcd3d76192e4007dfb496cca67e13b",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "d174ab98d277d9f5a5611c2c9f419d9f",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "57edf4a22be3c955ac49da2e2107b67a",
        )

        val sha1Digests = mapOf(
            "" to "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "a" to "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
            "abc" to "a9993e364706816aba3e25717850c26c9cd0d89d",
            "message digest" to "c12252ceda8be8994d5fa0290a47231c1d16aae3",
            "abcdefghijklmnopqrstuvwxyz" to "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "761c457bf73b14d27e9e9265c46f4b4dda11f940",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "50abf5706a150990a08b2c5ea40fa0e585554732",
        )

        val sha2256Digests = mapOf(
            "" to "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "a" to "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            "abc" to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "message digest" to "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
            "abcdefghijklmnopqrstuvwxyz" to "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
        )

        val sha2224Digests = mapOf(
            "" to "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        )

        val sha2512Digests = mapOf(
            "" to "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            "a" to "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
            "abc" to "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "message digest" to "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
            "abcdefghijklmnopqrstuvwxyz" to "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
            "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890" to "0d9a7df5b6a6ad20da519effda888a7344b6c0c7adcc8e2d504b4af27aaaacd4e7111c713f71769539629463cb58c86136c521b0414a3c0edf7dc6349c6edaf3",
        )

        val sha2384Digests = mapOf(
            "" to "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        )

        val sha2512224Digests = mapOf(
            "" to "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
        )

        val sha2512256Digests = mapOf(
            "" to "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        )

        val ripemd128Digests = mapOf(
            "" to "cdf26213a150dc3ecb610f18f6b38b46",
            "a" to "86be7afa339d0fc7cfc785e72f578d33",
            "abc" to "c14a12199c66e4ba84636b0f69144c77",
            "message digest" to "9e327b3d6e523062afc1132d7df9d1b8",
            "abcdefghijklmnopqrstuvwxyz" to "fd2aa607f71dc8f510714922b371834e",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" to "a1aa0689d0fafa2ddc22e88b49133a06",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "d1e959eb179c911faea4624c60c5c702",
            "1234567890".repeat(8) to "3f45ef194732c2dbb2c4a2c769795fa3",
            "a".repeat(1000000) to "4a7f5723f954eba1216c9d8f6320431f",
        )

        val ripemd160Digests = mapOf(
            "" to "9c1185a5c5e9fc54612808977ee8f548b2258d31",
            "a" to "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
            "abc" to "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
            "message digest" to "5d0689ef49d2fae572b881b123a85ffa21595f36",
            "abcdefghijklmnopqrstuvwxyz" to "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" to "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "b0e20b6e3116640286ed3a87a5713079b21f5189",
            "1234567890".repeat(8) to "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
            "a".repeat(1000000) to "52783243c1697bdbe16d37f97f68f08325dc1528",
        )

        fun testDigestAlgorithmAccuracy(da: DigestAlgorithm, digests: Map<String, String>) {
            for (digest in digests) {
                da.input(digest.key.toByteArrayFromAscii())
                assertTrue(da.digest().toHexString() == digest.value)
            }
        }

        fun testDigestAlgorithmOffsets(da: DigestAlgorithm, emptyDigest: ByteArray) {

            for (offset in 0 until buffer.size - da.digestLength) {

                println("offset = $offset")

                zeroedBuffer.copyInto(buffer)
                da.input(emptyBuffer)
                da.digest(buffer, offset)

                for (i in 0 until offset)
                    assertTrue(buffer[i] == 0.toByte())

                for (i in 0 until da.digestLength)
                    //assertTrue(buffer[offset + i] == emptyDigest[i])
                    println("expected: ${emptyDigest[i]}, found: ${buffer[offset + i]}")

                for (i in offset + da.digestLength until buffer.size)
                    assertTrue(buffer[i] == 0.toByte())
            }
        }

        val emptyBuffer = ByteArray(0)
        val zeroedBuffer = ByteArray(128)
        val buffer = ByteArray(128)
    }
}
