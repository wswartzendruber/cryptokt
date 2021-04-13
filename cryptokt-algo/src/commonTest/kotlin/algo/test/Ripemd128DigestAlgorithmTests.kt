/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

import org.cryptokt.algo.Ripemd128DigestAlgorithm

class Ripemd128DigestAlgorithmTests : DigestAlgorithmTests() {

    val digests = mapOf(

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

    override val configurations = mapOf(
        DigestAlgorithmConfiguration({ Ripemd128DigestAlgorithm() }, "RIPEMD-128") to digests,
    )
}
