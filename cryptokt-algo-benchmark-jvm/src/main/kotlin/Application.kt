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
import org.bouncycastle.crypto.digests.SHA3Digest
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
import org.cryptokt.algo.Sha3DigestAlgorithm
import org.cryptokt.algo.Sha3DigestSize
import org.cryptokt.algo.Sha512DigestAlgorithm

fun main() {

    val gigabyte = Random.nextBytes(ByteArray(1024 * 1024 * 1024))
    val password = Random.nextBytes(ByteArray(12))
    val output = ByteArray(1024)

    println("CryptoKt Algorithm Benchmarks for JVM")
    println()

    // println("MD2, 1M passwords")
    // println(" - Bouncy Castle: ${time { MD2Digest().digestPassword(password, output, 1000000) } }")
    // println(" - CryptoKt     : ${time { Md2DigestAlgorithm().digestPassword(password, output, 1000000) } }")
    // println("MD2, 1 GB")
    // println(" - Bouncy Castle: SKIPPED")
    // println(" - CryptoKt     : SKIPPED")
    // println()

    // println("MD4, 1M passwords")
    // println(" - Bouncy Castle: ${time { MD4Digest().digestPassword(password, output, 1000000) } }")
    // println(" - CryptoKt     : ${time { Md4DigestAlgorithm().digestPassword(password, output, 1000000) } }")
    // println("MD4, 1 GB")
    // println(" - Bouncy Castle: ${time { MD4Digest().transformBuffer(gigabyte) }}")
    // println(" - CryptoKt     : ${time { Md4DigestAlgorithm().transformBuffer(gigabyte) }}")
    // println()

    // println("MD5, 1M passwords")
    // println(" - Bouncy Castle: ${time { MD5Digest().digestPassword(password, output, 1000000) } }")
    // println(" - CryptoKt     : ${time { Md5DigestAlgorithm().digestPassword(password, output, 1000000) } }")
    // println("MD5, 1 GB")
    // println(" - Bouncy Castle: ${time { MD5Digest().transformBuffer(gigabyte) }}")
    // println(" - CryptoKt     : ${time { Md5DigestAlgorithm().transformBuffer(gigabyte) }}")
    // println()

    // println("SHA1, 1M passwords")
    // println(" - Bouncy Castle: ${time { SHA1Digest().digestPassword(password, output, 1000000) } }")
    // println(" - CryptoKt     : ${time { Sha1DigestAlgorithm().digestPassword(password, output, 1000000) } }")
    // println("SHA1, 1 GB")
    // println(" - Bouncy Castle: ${time { SHA1Digest().transformBuffer(gigabyte) }}")
    // println(" - CryptoKt     : ${time { Sha1DigestAlgorithm().transformBuffer(gigabyte) }}")
    // println()

    // println("SHA2-256, 1M passwords")
    // println(" - Bouncy Castle: ${time { SHA256Digest().digestPassword(password, output, 1000000) } }")
    // println(" - CryptoKt     : ${time { Sha256DigestAlgorithm().digestPassword(password, output, 1000000) } }")
    // println("SHA2-256, 1 GB")
    // println(" - Bouncy Castle: ${time { SHA256Digest().transformBuffer(gigabyte) }}")
    // println(" - CryptoKt     : ${time { Sha256DigestAlgorithm().transformBuffer(gigabyte) }}")
    // println()

    // println("SHA2-512, 1M passwords")
    // println(" - Bouncy Castle: ${time { SHA512Digest().digestPassword(password, output, 1000000) } }")
    // println(" - CryptoKt     : ${time { Sha512DigestAlgorithm().digestPassword(password, output, 1000000) } }")
    // println("SHA2-512, 1 GB")
    // println(" - Bouncy Castle: ${time { SHA512Digest().transformBuffer(gigabyte) }}")
    // println(" - CryptoKt     : ${time { Sha512DigestAlgorithm().transformBuffer(gigabyte) }}")
    // println()

    println("SHA3-256, 1M passwords")
    println(" - Bouncy Castle: ${time { SHA3Digest(256).digestPassword(password, output, 1000000) } }")
    println(" - CryptoKt     : ${time { Sha3DigestAlgorithm(Sha3DigestSize._256).digestPassword(password, output, 1000000) } }")
    println("SHA3-256, 1 GB")
    println(" - Bouncy Castle: ${time { SHA3Digest(256).transformBuffer(gigabyte) }}")
    println(" - CryptoKt     : ${time { Sha3DigestAlgorithm(Sha3DigestSize._256).transformBuffer(gigabyte) }}")
    println()

    println("SHA3-512, 1M passwords")
    println(" - Bouncy Castle: ${time { SHA3Digest(512).digestPassword(password, output, 1000000) } }")
    println(" - CryptoKt     : ${time { Sha3DigestAlgorithm(Sha3DigestSize._512).digestPassword(password, output, 1000000) } }")
    println("SHA3-512, 1 GB")
    println(" - Bouncy Castle: ${time { SHA3Digest(512).transformBuffer(gigabyte) }}")
    println(" - CryptoKt     : ${time { Sha3DigestAlgorithm(Sha3DigestSize._512).transformBuffer(gigabyte) }}")
    println()

    // println("RIPEMD-128, 1M passwords")
    // println(" - Bouncy Castle: ${time { RIPEMD128Digest().digestPassword(password, output, 1000000) } }")
    // println(" - CryptoKt     : ${time { Ripemd128DigestAlgorithm().digestPassword(password, output, 1000000) } }")
    // println("RIPEMD-128, 1 GB")
    // println(" - Bouncy Castle: ${time { RIPEMD128Digest().transformBuffer(gigabyte) }}")
    // println(" - CryptoKt     : ${time { Ripemd128DigestAlgorithm().transformBuffer(gigabyte) }}")
    // println()

    // println("RIPEMD-160, 1M passwords")
    // println(" - Bouncy Castle: ${time { RIPEMD160Digest().digestPassword(password, output, 1000000) } }")
    // println(" - CryptoKt     : ${time { Ripemd160DigestAlgorithm().digestPassword(password, output, 1000000) } }")
    // println("RIPEMD-160, 1 GB")
    // println(" - Bouncy Castle: ${time { RIPEMD160Digest().transformBuffer(gigabyte) }}")
    // println(" - CryptoKt     : ${time { Ripemd160DigestAlgorithm().transformBuffer(gigabyte) }}")
    // println()

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

fun Digest.digestPassword(input: ByteArray, output: ByteArray, count: Int) {
    repeat(count) {
        this.reset()
        this.update(input, 0, input.size)
        this.doFinal(output, 0)
    }
}

fun DigestAlgorithm.digestPassword(input: ByteArray, output: ByteArray, count: Int) {
    repeat(count) {
        this.reset()
        this.input(input)
        this.digest(output)
    }
}
