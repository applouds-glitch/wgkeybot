/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

/**
 * What the split-tunnel wizard's "selected apps bypass the VPN" starts with.
 *
 * That mode used to open on an empty list, so a user who picked it had to know
 * by themself which apps to tick, and the ones that matter most are the ones
 * they find out about the hard way: Russian banks, marketplaces and state
 * services that refuse a foreign address or a VPN outright, and local services
 * that need no tunnel and are only slowed by one. The picker shows these ticked
 * — the ones that are installed — and the user unticks what they want inside.
 *
 * Only the wizard's first choice starts from it. The picker opened later shows
 * what is saved, an empty list included: the user may have emptied it.
 *
 * The package names are the ones free-turn-proxy 5.3 ships as its default
 * bypass list, without the vendors' system apps: the picker hides system apps
 * by default, and a tick the user cannot see is not theirs.
 */
internal object SplitTunnelPreset {
    val BYPASS: List<String> = listOf(
        // Marketplaces, delivery, taxi
        "ru.wildberries.buyer",
        "ru.ozon.app.android",
        "ru.sbermegamarket.app",
        "ru.samokat.app",
        "ru.yandex.market",
        "ru.yandex.eda",
        "ru.yandex.taxi",
        // Maps and Yandex services
        "ru.dublgis.dgismobile",
        "com.yandex.browser",
        "ru.yandex.yandexmaps",
        "ru.yandex.music",
        "ru.kinopoisk",
        // Social and media
        "ru.oneme.app",
        "ru.vk.store",
        "ru.ok.android",
        "com.vkontakte.android",
        "ru.vk.video",
        "ru.rutube.app",
        "com.zen.android",
        // Banks and payments
        "ru.sberbankmobile",
        "com.tinkoff.itinkoff",
        "ru.tbank.mobile",
        "ru.alfabank.mobile.android",
        "ru.vtb24.mobileandroid",
        "ru.nspk.mirpay",
        // State services
        "ru.gosuslugi.app",
        "ru.rzd.pass",
        "ru.mos.parking",
        // Carriers
        "ru.megafon.mlk",
        "ru.beeline.services",
        "ru.tele2.mytele2",
        // Classifieds, jobs, mail
        "com.avito.android",
        "ru.hh.android",
        "ru.cian.main",
        "ru.mail.mailapp",
    )

    /** The wizard's starting selection for the tab it opens. */
    fun forWizard(excluded: Boolean): List<String> = if (excluded) BYPASS else emptyList()
}
