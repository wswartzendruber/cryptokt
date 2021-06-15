/*
 * SPDX-FileCopyrightText: 2020 William Swartzendruber <wswartzendruber@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.cryptokt.algo

/**
 * Represents the possible digest sizes for SHA2-256.
 */
public enum class Sha256DigestSize(
    internal val digestSize: Int,
    internal val rc: Int,
    internal val cr: IntArray,
) {
    /** SHA2-224. The digest size is 28 bytes. */
    _224(
        28,
        7,
        intArrayOf(
            -1056596264, 914150663, 812702999, -150054599,
            -4191439, 1750603025, 1694076839, -1090891868,
        ),
    ),
    /** SHA2-256. The digest size is 32 bytes. */
    _256(
        32,
        8,
        intArrayOf(
            1779033703, -1150833019, 1013904242, -1521486534,
            1359893119, -1694144372, 528734635, 1541459225,
        ),
    ),
}
