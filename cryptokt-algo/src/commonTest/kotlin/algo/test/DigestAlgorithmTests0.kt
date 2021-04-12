/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

import kotlin.test.assertTrue
import kotlin.test.Test

import org.cryptokt.algo.DigestAlgorithm
import org.cryptokt.algo.Ripemd128DigestAlgorithm
import org.cryptokt.algo.Ripemd160DigestAlgorithm
import org.cryptokt.algo.Sha256DigestAlgorithm
import org.cryptokt.algo.Sha256DigestSize
import org.cryptokt.algo.Sha3DigestAlgorithm
import org.cryptokt.algo.Sha3DigestSize
import org.cryptokt.algo.Sha512DigestAlgorithm
import org.cryptokt.algo.Sha512DigestSize

class DigestAlgorithmTests0 {

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

    @Test
    fun SHA3_224_accuracy() {
        println(Sha3DigestAlgorithm(Sha3DigestSize._224).digest().toHexString())
        testDigestAlgorithmAccuracy(
            Sha3DigestAlgorithm(Sha3DigestSize._224), sha3224Digests
        )
    }

    @Test
    fun SHA3_256_accuracy() {
        println(Sha3DigestAlgorithm(Sha3DigestSize._256).digest().toHexString())
        testDigestAlgorithmAccuracy(
            Sha3DigestAlgorithm(Sha3DigestSize._256), sha3256Digests
        )
    }
    @Test
    fun SHA3_384_accuracy() {
        testDigestAlgorithmAccuracy(
            Sha3DigestAlgorithm(Sha3DigestSize._384), sha3384Digests
        )
    }

    @Test
    fun SHA3_512_accuracy() {
        testDigestAlgorithmAccuracy(
            Sha3DigestAlgorithm(Sha3DigestSize._512), sha3512Digests
        )
    }

    companion object {

        val sha2256Digests = mapOf(

            "".toByteArrayFromAscii()
            to
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",

            "a".toByteArrayFromAscii()
            to
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",

            "abc".toByteArrayFromAscii()
            to
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",

            "message digest".toByteArrayFromAscii()
            to
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",

            "abcdefghijklmnopqrstuvwxyz".toByteArrayFromAscii()
            to
            "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",

            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArrayFromAscii()
            to
            "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",

            "12345678901234567890123456789012345678901234567890123456789012345678901234567890".toByteArrayFromAscii()
            to
            "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
        )

        val sha2224Digests = mapOf(

            "".toByteArrayFromAscii()
            to
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        )

        val sha2512Digests = mapOf(

            "".toByteArrayFromAscii()
            to
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",

            "a".toByteArrayFromAscii()
            to
            "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",

            "abc".toByteArrayFromAscii()
            to
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",

            "message digest".toByteArrayFromAscii()
            to
            "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",

            "abcdefghijklmnopqrstuvwxyz".toByteArrayFromAscii()
            to
            "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",

            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArrayFromAscii()
            to
            "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",

            "12345678901234567890123456789012345678901234567890123456789012345678901234567890".toByteArrayFromAscii()
            to
            "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",

            "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".toByteArrayFromAscii()
            to
            "0d9a7df5b6a6ad20da519effda888a7344b6c0c7adcc8e2d504b4af27aaaacd4e7111c713f71769539629463cb58c86136c521b0414a3c0edf7dc6349c6edaf3",
        )

        val sha2384Digests = mapOf(

            "".toByteArrayFromAscii()
            to
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        )

        val sha2512224Digests = mapOf(

            "".toByteArrayFromAscii()
            to
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
        )

        val sha2512256Digests = mapOf(

            "".toByteArrayFromAscii()
            to
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        )

        val ripemd128Digests = mapOf(

            "".toByteArrayFromAscii()
            to
            "cdf26213a150dc3ecb610f18f6b38b46",

            "a".toByteArrayFromAscii()
            to
            "86be7afa339d0fc7cfc785e72f578d33",

            "abc".toByteArrayFromAscii()
            to
            "c14a12199c66e4ba84636b0f69144c77",

            "message digest".toByteArrayFromAscii()
            to
            "9e327b3d6e523062afc1132d7df9d1b8",

            "abcdefghijklmnopqrstuvwxyz".toByteArrayFromAscii()
            to
            "fd2aa607f71dc8f510714922b371834e",

            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toByteArrayFromAscii()
            to
            "a1aa0689d0fafa2ddc22e88b49133a06",

            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArrayFromAscii()
            to
            "d1e959eb179c911faea4624c60c5c702",

            "1234567890".repeat(8).toByteArrayFromAscii()
            to
            "3f45ef194732c2dbb2c4a2c769795fa3",

            "a".repeat(1000000).toByteArrayFromAscii()
            to
            "4a7f5723f954eba1216c9d8f6320431f",
        )

        val ripemd160Digests = mapOf(

            "".toByteArrayFromAscii()
            to
            "9c1185a5c5e9fc54612808977ee8f548b2258d31",

            "a".toByteArrayFromAscii()
            to
            "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",

            "abc".toByteArrayFromAscii()
            to
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",

            "message digest".toByteArrayFromAscii()
            to
            "5d0689ef49d2fae572b881b123a85ffa21595f36",

            "abcdefghijklmnopqrstuvwxyz".toByteArrayFromAscii()
            to
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",

            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toByteArrayFromAscii()
            to
            "12a053384a9c0c88e405a06c27dcf49ada62eb2b",

            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArrayFromAscii()
            to
            "b0e20b6e3116640286ed3a87a5713079b21f5189",

            "1234567890".repeat(8).toByteArrayFromAscii()
            to
            "9b752e45573d4b39f4dbd3323cab82bf63326bfb",

            "a".repeat(1000000).toByteArrayFromAscii()
            to
            "52783243c1697bdbe16d37f97f68f08325dc1528",
        )

        val sha3224Digests = mapOf(

            "".toByteArrayFromHex()
            to
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        )

        val sha3256Digests = mapOf(

            "".toByteArrayFromHex()
            to
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )

        val sha3384Digests = mapOf(

            "".toByteArrayFromHex()
            to
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        )

        val sha3512Digests = mapOf(

            "".toByteArrayFromHex()
            to
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",

            "ec83d707a1414a".toByteArrayFromHex()
            to
            "84fd3775bac5b87e550d03ec6fe4905cc60e851a4c33a61858d4e7d8a34d471f05008b9a1d63044445df5a9fce958cb012a6ac778ecf45104b0fcb979aa4692d",

            "14cb35fa933e49b0d0a400183cbbea099c44995fae1163".toByteArrayFromHex()
            to
            "af2ef4b0c01e381b4c382208b66ad95d759ec91e386e953984aa5f07774632d53b581eba32ed1d369c46b0a57fee64a02a0e5107c22f14f2227b1d11424becb5",

            "a60b7b3df15b3f1b19db15d480388b0f3b00837369aa2cc7c3d7315775d7309a2d6f6d1371d9c875350dec0a".toByteArrayFromHex()
            to
            "8d651605c6b32bf022ea06ce6306b2ca6b5ba2781af87ca2375860315c83ad88743030d148ed8d73194c461ec1e84c045fc914705747614c04c8865b51da94f7",

            "0ce9f8c3a990c268f34efd9befdb0f7c4ef8466cfdb01171f8de70dc5fefa92acbe93d29e2ac1a5c2979129f1ab08c0e77de7924ddf68a209cdfa0adc62f85c18637d9c6b33f4ff8".toByteArrayFromHex()
            to
            "b018a20fcf831dde290e4fb18c56342efe138472cbe142da6b77eea4fce52588c04c808eb32912faa345245a850346faec46c3a16d39bd2e1ddb1816bc57d2da",
        )

        fun testDigestAlgorithmAccuracy(da: DigestAlgorithm, digests: Map<ByteArray, String>) {
            for (digest in digests) {
                da.input(digest.key)
                assertTrue(da.digest().toHexString() == digest.value)
            }
        }
    }
}
