/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
 */

package org.cryptokt.algo.test

import org.cryptokt.algo.Sha512DigestSize
import org.cryptokt.algo.Sha512DigestAlgorithm

class Sha512DigestAlgorithmTests : DigestAlgorithmTests() {

    val digests224 = mapOf(

        "".toByteArrayFromAscii()
        to
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
    )

    val digests256 = mapOf(

        "".toByteArrayFromAscii()
        to
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
    )

    val digests384 = mapOf(

        "".toByteArrayFromAscii()
        to
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51a" +
            "d2f14898b95b",
    )

    val digests512 = mapOf(

        "".toByteArrayFromAscii()
        to
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff83" +
            "18d2877eec2f63b931bd47417a81a538327af927da3e",

        "a".toByteArrayFromAscii()
        to
        "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252" +
            "aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",

        "abc".toByteArrayFromAscii()
        to
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba" +
            "3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",

        "message digest".toByteArrayFromAscii()
        to
        "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a" +
            "905d5597b72038ddb372a89826046de66687bb420e7c",

        "abcdefghijklmnopqrstuvwxyz".toByteArrayFromAscii()
        to
        "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe" +
            "3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",

        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArrayFromAscii()
        to
        "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90" +
            "041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",

        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            .toByteArrayFromAscii()
        to
        "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456" +
            "764346900cb130d2a4fd5dd16abb5e30bcb850dee843",

        ("12345678901234567890123456789012345678901234567890123456789012345678901234567890123" +
            "4567890123456789012345678901234567890").toByteArrayFromAscii()
        to
        "0d9a7df5b6a6ad20da519effda888a7344b6c0c7adcc8e2d504b4af27aaaacd4e7111c713f7176953962" +
            "9463cb58c86136c521b0414a3c0edf7dc6349c6edaf3",
    )

    override val configurations = mapOf(

            DigestAlgorithmConfiguration(
                { Sha512DigestAlgorithm(Sha512DigestSize._224) },
                "SHA2-512/224",
            )
            to
            digests224,

            DigestAlgorithmConfiguration(
                { Sha512DigestAlgorithm(Sha512DigestSize._256) },
                "SHA2-512/256",
            )
            to
            digests256,

            DigestAlgorithmConfiguration(
                { Sha512DigestAlgorithm(Sha512DigestSize._384) },
                "SHA2-384",
            )
            to
            digests384,

            DigestAlgorithmConfiguration(
                { Sha512DigestAlgorithm(Sha512DigestSize._512) },
                "SHA2-512",
            )
            to
            digests512,
        )
}
