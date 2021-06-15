/*
 * SPDX-FileCopyrightText: 2021 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: CC0-1.0
 */

package org.cryptokt.algo.test

internal expect fun String.toByteArrayFromAscii(): ByteArray

internal expect fun String.toByteArrayFromHex(): ByteArray

internal expect fun ByteArray.toHexString(): String
