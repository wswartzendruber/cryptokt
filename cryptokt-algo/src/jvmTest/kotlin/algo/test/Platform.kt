/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

import java.nio.charset.Charset

import org.apache.commons.codec.binary.Hex

private val charset = Charset.forName("US-ASCII")

internal actual fun String.toByteArrayFromAscii() = this.toByteArray(charset)

internal actual fun String.toByteArrayFromHex() = Hex.decodeHex(this)

internal actual fun ByteArray.toHexString() = Hex.encodeHexString(this)
