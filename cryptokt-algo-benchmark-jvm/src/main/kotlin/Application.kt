/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.benchmark.jvm

import java.util.Date
import kotlin.random.Random

import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.MD2Digest
import org.bouncycastle.crypto.digests.MD4Digest
import org.bouncycastle.crypto.digests.MD5Digest
import org.bouncycastle.crypto.digests.RIPEMD128Digest
import org.bouncycastle.crypto.digests.RIPEMD160Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.cryptokt.algo.DigestAlgorithm
import org.cryptokt.algo.Md2DigestAlgorithm
import org.cryptokt.algo.Md4DigestAlgorithm
import org.cryptokt.algo.Md5DigestAlgorithm
import org.cryptokt.algo.Ripemd128DigestAlgorithm
import org.cryptokt.algo.Ripemd160DigestAlgorithm
import org.cryptokt.algo.Sha1DigestAlgorithm
import org.cryptokt.algo.Sha256DigestAlgorithm
import org.cryptokt.algo.Sha512DigestAlgorithm

fun main() {

    val megabyte = Random.nextBytes(ByteArray(1024 * 1024))
    val gigabyte = Random.nextBytes(ByteArray(1024 * 1024 * 1024))

    println("CryptoKt Algorithm Benchmarks for JVM")
    println()

    println("MD2, 1 MB")
    println("- Bouncy Castle: ${time { MD2Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Md2DigestAlgorithm().transformBuffer(megabyte) }}")

    println("MD2, 1 GB")
    println("- Bouncy Castle: ${time { MD2Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Md2DigestAlgorithm().transformBuffer(gigabyte) }}")

    println("MD4, 1 MB")
    println("- Bouncy Castle: ${time { MD4Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Md4DigestAlgorithm().transformBuffer(megabyte) }}")

    println("MD4, 1 GB")
    println("- Bouncy Castle: ${time { MD4Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Md4DigestAlgorithm().transformBuffer(gigabyte) }}")

    println("MD5, 1 MB")
    println("- Bouncy Castle: ${time { MD5Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Md5DigestAlgorithm().transformBuffer(megabyte) }}")

    println("MD5, 1 GB")
    println("- Bouncy Castle: ${time { MD5Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Md5DigestAlgorithm().transformBuffer(gigabyte) }}")

    println("SHA1, 1 MB")
    println("- Bouncy Castle: ${time { SHA1Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Sha1DigestAlgorithm().transformBuffer(megabyte) }}")

    println("SHA1, 1 GB")
    println("- Bouncy Castle: ${time { SHA1Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Sha1DigestAlgorithm().transformBuffer(gigabyte) }}")

    println("SHA256, 1 MB")
    println("- Bouncy Castle: ${time { SHA256Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Sha256DigestAlgorithm().transformBuffer(megabyte) }}")

    println("SHA256, 1 GB")
    println("- Bouncy Castle: ${time { SHA256Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Sha256DigestAlgorithm().transformBuffer(gigabyte) }}")

    println("SHA512, 1 MB")
    println("- Bouncy Castle: ${time { SHA512Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Sha512DigestAlgorithm().transformBuffer(megabyte) }}")

    println("SHA512, 1 GB")
    println("- Bouncy Castle: ${time { SHA512Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Sha512DigestAlgorithm().transformBuffer(gigabyte) }}")

    println("RIPEMD-128, 1 MB")
    println("- Bouncy Castle: ${time { RIPEMD128Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Ripemd128DigestAlgorithm().transformBuffer(megabyte) }}")

    println("RIPEMD-128, 1 GB")
    println("- Bouncy Castle: ${time { RIPEMD128Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Ripemd128DigestAlgorithm().transformBuffer(gigabyte) }}")

    println("RIPEMD-160, 1 MB")
    println("- Bouncy Castle: ${time { RIPEMD160Digest().transformBuffer(megabyte) }}")
    println("- CryptoKt     : ${time { Ripemd160DigestAlgorithm().transformBuffer(megabyte) }}")

    println("RIPEMD-160, 1 GB")
    println("- Bouncy Castle: ${time { RIPEMD160Digest().transformBuffer(gigabyte) }}")
    println("- CryptoKt     : ${time { Ripemd160DigestAlgorithm().transformBuffer(gigabyte) }}")

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

fun DigestAlgorithm.transformBuffer(buffer: ByteArray) {
    this.input(buffer)
    this.digest()
}
