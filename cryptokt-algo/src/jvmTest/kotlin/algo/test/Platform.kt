/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

import java.nio.charset.Charset

private val charset = Charset.forName("US-ASCII")

internal actual fun String.toAsciiByteArray() = this.toByteArray(charset)

internal actual fun ByteArray.toHexString() =
    this.joinToString("") { String.format("%02x", it) }
