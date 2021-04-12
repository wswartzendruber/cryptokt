/*
 * Copyright 2020 William Swartzendruber
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
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
