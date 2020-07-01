/*
 * Copyright 2020 William Swartzendruber
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a
 * copy of the MPL was not distributed with this file, You can obtain one at
 * https://mozilla.org/MPL/2.0/.
 */

package org.cryptokt.algo.benchmark.jvm

import java.util.Date
import kotlin.random.Random

import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.MD2Digest
import org.bouncycastle.crypto.digests.MD4Digest
import org.bouncycastle.crypto.digests.MD5Digest
import org.bouncycastle.crypto.digests.RIPEMD160Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.cryptokt.algo.Hash
import org.cryptokt.algo.Md2Hash
import org.cryptokt.algo.Md4Hash
import org.cryptokt.algo.Md5Hash
import org.cryptokt.algo.Ripemd160Hash
import org.cryptokt.algo.Sha1Hash
import org.cryptokt.algo.Sha256Hash
import org.cryptokt.algo.Sha512Hash

fun main(args: Array<String>) {

    val megabyte = Random.nextBytes(ByteArray(1024 * 1024))
    val gigabyte = Random.nextBytes(ByteArray(1024 * 1024 * 1024))

    println("CryptoKt Algorithm Benchmarks for JVM")
    println()

    // println("MD2, 1 MB")
    // println("- Bouncy Castle: ${time { MD2Digest().transformBuffer(megabyte) }}")
    // println("- CryptoKt     : ${time { Md2Hash().transformBuffer(megabyte) }}")

    // println("MD2, 1 GB")
    // println("- Bouncy Castle: ${time { MD2Digest().transformBuffer(gigabyte) }}")
    // println("- CryptoKt     : ${time { Md2Hash().transformBuffer(gigabyte) }}")

    println("MD4, 1 MB")
    println("- Bouncy Castle: ${time { MD4Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Md4Hash().transformBuffer(megabyte) }}")

    println("MD4, 1 GB")
    println("- Bouncy Castle: ${time { MD4Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Md4Hash().transformBuffer(gigabyte) }}")

    println("MD5, 1 MB")
    println("- Bouncy Castle: ${time { MD5Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Md5Hash().transformBuffer(megabyte) }}")

    println("MD5, 1 GB")
    println("- Bouncy Castle: ${time { MD5Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Md5Hash().transformBuffer(gigabyte) }}")

    println("SHA1, 1 MB")
    println("- Bouncy Castle: ${time { SHA1Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Sha1Hash().transformBuffer(megabyte) }}")

    println("SHA1, 1 GB")
    println("- Bouncy Castle: ${time { SHA1Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Sha1Hash().transformBuffer(gigabyte) }}")

    println("SHA256, 1 MB")
    println("- Bouncy Castle: ${time { SHA256Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Sha256Hash().transformBuffer(megabyte) }}")

    println("SHA256, 1 GB")
    println("- Bouncy Castle: ${time { SHA256Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Sha256Hash().transformBuffer(gigabyte) }}")

    println("SHA512, 1 MB")
    println("- Bouncy Castle: ${time { SHA512Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Sha512Hash().transformBuffer(megabyte) }}")

    println("SHA512, 1 GB")
    println("- Bouncy Castle: ${time { SHA512Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Sha512Hash().transformBuffer(gigabyte) }}")

    println("RIPEMD-160, 1 MB")
    println("- Bouncy Castle: ${time { RIPEMD160Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Ripemd160Hash().transformBuffer(megabyte) }}")

    println("RIPEMD-160, 1 GB")
    println("- Bouncy Castle: ${time { RIPEMD160Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Ripemd160Hash().transformBuffer(gigabyte) }}")

}

fun time(block: () -> Unit): Long {

    val start = Date().time

    block()

    return Date().time - start
}

fun Digest.transformBuffer(buffer: ByteArray) {
    this.update(buffer, 0, buffer.size)
    this.doFinal(ByteArray(this.digestSize), 0)
}

fun Hash.transformBuffer(buffer: ByteArray) {
    this.input(buffer)
    this.digest()
}
