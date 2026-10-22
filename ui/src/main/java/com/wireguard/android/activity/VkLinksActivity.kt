/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.Context
import android.os.Bundle
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.core.view.updatePadding
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.backend.TurnBackend
import com.wireguard.android.databinding.VkLinksActivityBinding
import com.wireguard.android.turn.ExpertSettings
import com.wireguard.android.turn.VkLinkChecker
import com.wireguard.android.turn.VkLinks
import com.wireguard.android.util.localeWrapped
import com.wireguard.android.util.lockPortraitOnPhone
import kotlinx.coroutines.launch

/**
 * Expert mode's VK call links: the user's own list, which stands in for the
 * bot's at the next connection, and the bot's for comparison — each with a
 * check against VK that says whether the call still admits anonymous joins.
 *
 * Checking and saving are separate buttons: a check is a question to VK about
 * a list, a save is a decision about the next connect, and either is wanted
 * without the other (checking the bot's links changes nothing; saving links
 * that failed the check is the user's call). The verdicts come from
 * [VkLinkChecker], which outlives this screen: a check is seconds per link and
 * up to ~45 s for one VK cannot reach, and backing out must not lose it.
 */
class VkLinksActivity : AppCompatActivity() {

    override fun attachBaseContext(newBase: Context) = super.attachBaseContext(newBase.localeWrapped())

    private lateinit var binding: VkLinksActivityBinding
    private val expert: ExpertSettings get() = ExpertSettings.getInstance(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lockPortraitOnPhone()
        enableEdgeToEdge()
        binding = VkLinksActivityBinding.inflate(layoutInflater)
        setContentView(binding.root)
        applyInsets()
        binding.wgkLinksToolbar.setNavigationOnClickListener { finish() }

        // The field keeps its own text through a recreation; only a fresh
        // start reads the store.
        if (savedInstanceState == null) binding.wgkLinksInput.setText(expert.vkLinksText())
        binding.wgkLinksCheckBtn.setOnClickListener { checkOwn() }
        binding.wgkLinksSaveBtn.setOnClickListener { save() }

        binding.wgkLinksConfigRow.apply {
            wgkRowIcon.setImageResource(R.drawable.ic_key)
            wgkRowLabel.text = getString(R.string.wgk_vk_links_config_count, configHashes().size)
            wgkRowValue.isVisible = false
            wgkRowChevron.isVisible = false
            wgkRowBtn.isClickable = false
            wgkRowBtn.isFocusable = false
        }
        binding.wgkLinksConfigCheckBtn.setOnClickListener { checkConfig() }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) { VkLinkChecker.state.collect { render(it) } }
        }
    }

    private fun applyInsets() {
        ViewCompat.setOnApplyWindowInsetsListener(binding.wgkLinksRoot) { _, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            binding.wgkLinksToolbar.updatePadding(top = bars.top, left = bars.left, right = bars.right)
            binding.wgkLinksScroll.updatePadding(left = bars.left, right = bars.right, bottom = bars.bottom)
            WindowInsetsCompat.CONSUMED
        }
    }

    /** The bot's links as join hashes — what a start would join with. */
    private fun configHashes(): List<String> {
        val vkLink = Application.getTunnelManager().primaryTunnelOrNull()?.turnSettings?.vkLink.orEmpty()
        return VkLinks.split(vkLink).mapNotNull { VkLinks.hash(it) }
    }

    /**
     * What the field holds, with the problems said under it. Null when there is
     * something the user has to fix first; the cap only trims and says so.
     */
    private fun ownHashes(): VkLinks.Parsed? {
        val parsed = VkLinks.parse(binding.wgkLinksInput.text?.toString().orEmpty())
        binding.wgkLinksInputLayout.error = parsed.invalid.firstOrNull()?.let { getString(R.string.wgk_vk_links_invalid, it) }
        if (parsed.invalid.isNotEmpty()) return null
        if (parsed.truncated) Toast.makeText(this, R.string.wgk_vk_links_too_many, Toast.LENGTH_SHORT).show()
        return parsed
    }

    private fun save() {
        if (ownHashes() == null) return
        expert.setVkLinksText(binding.wgkLinksInput.text?.toString().orEmpty())
        Toast.makeText(this, R.string.wgk_vk_links_saved, Toast.LENGTH_SHORT).show()
    }

    private fun checkOwn() {
        val parsed = ownHashes() ?: return
        startCheck(VkLinkChecker.Target.OWN, parsed.hashes, binding.wgkLinksOwnStatus)
    }

    private fun checkConfig() = startCheck(VkLinkChecker.Target.CONFIG, configHashes(), binding.wgkLinksConfigStatus)

    private fun startCheck(target: VkLinkChecker.Target, hashes: List<String>, status: TextView) {
        if (hashes.isEmpty()) {
            status.setText(R.string.wgk_vk_links_none)
            status.isVisible = true
            return
        }
        if (!VkLinkChecker.start(target, hashes)) {
            Toast.makeText(this, R.string.wgk_vk_links_busy, Toast.LENGTH_SHORT).show()
        }
    }

    private fun render(progress: VkLinkChecker.Progress) {
        binding.wgkLinksCheckBtn.isEnabled = !progress.running
        binding.wgkLinksConfigCheckBtn.isEnabled = !progress.running
        val status = when (progress.target) {
            VkLinkChecker.Target.OWN -> binding.wgkLinksOwnStatus
            VkLinkChecker.Target.CONFIG -> binding.wgkLinksConfigStatus
            null -> return
        }
        val lines = ArrayList<String>()
        if (progress.running) {
            lines.add(getString(R.string.wgk_vk_links_checking, progress.results.size + 1, progress.total))
        }
        progress.results.mapTo(lines) { verdictLine(it) }
        status.text = lines.joinToString("\n")
        status.isVisible = lines.isNotEmpty()
    }

    private fun verdictLine(result: VkLinkChecker.Result): String {
        val res = when (result.code) {
            TurnBackend.LINK_CHECK_OK -> R.string.wgk_vk_links_result_ok
            TurnBackend.LINK_CHECK_REQUIRES_AUTH -> R.string.wgk_vk_links_result_auth
            TurnBackend.LINK_CHECK_UNAVAILABLE -> R.string.wgk_vk_links_result_dead
            TurnBackend.LINK_CHECK_CAPTCHA -> R.string.wgk_vk_links_result_captcha
            TurnBackend.LINK_CHECK_TEMPORARY -> R.string.wgk_vk_links_result_temporary
            else -> R.string.wgk_vk_links_result_error
        }
        return getString(res, result.index + 1)
    }
}
