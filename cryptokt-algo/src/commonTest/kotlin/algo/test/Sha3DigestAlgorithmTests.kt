/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
 */

package org.cryptokt.algo.test

import org.cryptokt.algo.Sha3DigestSize
import org.cryptokt.algo.Sha3DigestAlgorithm

class Sha3DigestAlgorithmTests : DigestAlgorithmTests() {

    val digests224 = mapOf(

        "".toByteArrayFromHex()
        to
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
    )

    val digests256 = mapOf(

        "".toByteArrayFromHex()
        to
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    )

    val digests384 = mapOf(

        "".toByteArrayFromHex()
        to
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6b" +
            "d1e058d5f004",
    )

    val digests512 = mapOf(

        "".toByteArrayFromHex()
        to
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3" +
            "e9402c3ac558f500199d95b6d3e301758586281dcd26",

        "ec83d707a1414a".toByteArrayFromHex()
        to
        "84fd3775bac5b87e550d03ec6fe4905cc60e851a4c33a61858d4e7d8a34d471f05008b9a1d63044445df" +
            "5a9fce958cb012a6ac778ecf45104b0fcb979aa4692d",

        "14cb35fa933e49b0d0a400183cbbea099c44995fae1163".toByteArrayFromHex()
        to
        "af2ef4b0c01e381b4c382208b66ad95d759ec91e386e953984aa5f07774632d53b581eba32ed1d369c46" +
            "b0a57fee64a02a0e5107c22f14f2227b1d11424becb5",

        ("a60b7b3df15b3f1b19db15d480388b0f3b00837369aa2cc7c3d7315775d7309a2d6f6d1371d9c875350" +
            "dec0a").toByteArrayFromHex()
        to
        "8d651605c6b32bf022ea06ce6306b2ca6b5ba2781af87ca2375860315c83ad88743030d148ed8d73194c" +
            "461ec1e84c045fc914705747614c04c8865b51da94f7",

        ("0ce9f8c3a990c268f34efd9befdb0f7c4ef8466cfdb01171f8de70dc5fefa92acbe93d29e2ac1a5c297" +
            "9129f1ab08c0e77de7924ddf68a209cdfa0adc62f85c18637d9c6b33f4ff8")
            .toByteArrayFromHex()
        to
        "b018a20fcf831dde290e4fb18c56342efe138472cbe142da6b77eea4fce52588c04c808eb32912faa345" +
            "245a850346faec46c3a16d39bd2e1ddb1816bc57d2da",
    )

    override val configurations = mapOf(

            DigestAlgorithmConfiguration(
                { Sha3DigestAlgorithm(Sha3DigestSize._224) },
                "SHA3-224",
            )
            to
            digests224,

            DigestAlgorithmConfiguration(
                { Sha3DigestAlgorithm(Sha3DigestSize._256) },
                "SHA3-256",
            )
            to
            digests256,

            DigestAlgorithmConfiguration(
                { Sha3DigestAlgorithm(Sha3DigestSize._384) },
                "SHA3-384",
            )
            to
            digests384,

            DigestAlgorithmConfiguration(
                { Sha3DigestAlgorithm(Sha3DigestSize._512) },
                "SHA3-512",
            )
            to
            digests512,
        )
}
