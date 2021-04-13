/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

import org.cryptokt.algo.Sha256DigestSize
import org.cryptokt.algo.Sha256DigestAlgorithm

class Sha256DigestAlgorithmTests : DigestAlgorithmTests() {

    val digests224 = mapOf(

        "".toByteArrayFromAscii()
        to
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    )

    val digests256 = mapOf(

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

        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            .toByteArrayFromAscii()
        to
        "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
    )

    override val configurations = mapOf(

            DigestAlgorithmConfiguration(
                { Sha256DigestAlgorithm(Sha256DigestSize._224) },
                "SHA2-224",
            )
            to
            digests224,

            DigestAlgorithmConfiguration(
                { Sha256DigestAlgorithm(Sha256DigestSize._256) },
                "SHA2-256",
            )
            to
            digests256,
        )
}
