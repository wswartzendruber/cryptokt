/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

internal actual fun String.toAsciiByteArray() =
    this.let { input ->
        js("new TextEncoder().encode(input)")
    }

internal actual fun ByteArray.toHexString() =
    this.let { input ->
        js("""
            Array.from(input, function(byte) {
                return ("0" + (byte & 0xFF).toString(16)).slice(-2);
            }).join("")
        """)
    }
