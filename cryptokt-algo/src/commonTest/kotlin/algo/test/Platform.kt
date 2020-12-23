/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

internal expect fun String.toByteArrayFromAscii(): ByteArray

internal expect fun String.toByteArrayFromHex(): ByteArray

internal expect fun ByteArray.toHexString(): String
