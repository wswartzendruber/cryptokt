/*
 * Any copyright is dedicated to the Public Domain.
 * https://creativecommons.org/publicdomain/zero/1.0/
 */

package org.cryptokt.algo.test

internal actual fun String.toByteArrayFromAscii() =
    this.let {
        js("new TextEncoder().encode(it)")
    }

internal actual fun String.toByteArrayFromHex() =
    this.let {
        js("Int8Array.from(Buffer.from(it, 'hex'))")
    }

internal actual fun ByteArray.toHexString() =
    this.let {
        js("""
            Array.from(it, function(byte) {
                return ("0" + (byte & 0xFF).toString(16)).slice(-2);
            }).join("")
        """)
    }
