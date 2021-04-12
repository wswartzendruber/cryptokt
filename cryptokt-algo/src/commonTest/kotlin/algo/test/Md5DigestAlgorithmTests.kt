/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

import org.cryptokt.algo.Md5DigestAlgorithm

class Md5DigestAlgorithmTests : DigestAlgorithmTests() {

    override val digests = mapOf(

        "".toByteArrayFromAscii()
        to
        "d41d8cd98f00b204e9800998ecf8427e",

        "a".toByteArrayFromAscii()
        to
        "0cc175b9c0f1b6a831c399e269772661",

        "abc".toByteArrayFromAscii()
        to
        "900150983cd24fb0d6963f7d28e17f72",

        "message digest".toByteArrayFromAscii()
        to
        "f96b697d7cb7938d525a2f31aaf161d0",

        "abcdefghijklmnopqrstuvwxyz".toByteArrayFromAscii()
        to
        "c3fcd3d76192e4007dfb496cca67e13b",

        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toByteArrayFromAscii()
        to
        "d174ab98d277d9f5a5611c2c9f419d9f",

        "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            .toByteArrayFromAscii()
        to
        "57edf4a22be3c955ac49da2e2107b67a",
    )

    override fun newDigestAlgorithm() = Md5DigestAlgorithm()
}
