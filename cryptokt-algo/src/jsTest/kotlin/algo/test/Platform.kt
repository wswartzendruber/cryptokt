/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
 */

package org.cryptokt.algo.test

internal actual fun String.toByteArrayFromAscii(): ByteArray =
    this.let {
        js("new TextEncoder().encode(it)")
    }

internal actual fun String.toByteArrayFromHex(): ByteArray =
    this.let {
        js("Int8Array.from(Buffer.from(it, 'hex'))")
    }

internal actual fun ByteArray.toHexString(): String =
    this.let {
        js("""
            Array.from(it, function(byte) {
                return ("0" + (byte & 0xFF).toString(16)).slice(-2);
            }).join("")
        """)
    }
