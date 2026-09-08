package com.wireguard.android.updater

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.format.Formatter
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import androidx.core.view.updatePadding
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.wireguard.android.BuildConfig
import com.wireguard.android.R
import com.wireguard.android.databinding.UpdateActivityBinding
import com.wireguard.android.util.localeWrapped
import kotlinx.coroutines.launch

/** Shared by the phone and TV; all actions are ordinary D-pad focusable buttons. */
class UpdateActivity : AppCompatActivity() {
    private lateinit var binding: UpdateActivityBinding
    private var permissionRequested = false
    private var permissionInFlight = false

    private val permissionLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        permissionInFlight = false
        if (canInstall()) AppUpdater.install(this)
        else render(AppUpdater.state.value)
    }
    private val confirmationLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        AppUpdater.confirmationReturned(this)
    }

    override fun attachBaseContext(newBase: Context) = super.attachBaseContext(newBase.localeWrapped())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        binding = UpdateActivityBinding.inflate(layoutInflater)
        setContentView(binding.root)
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            view.updatePadding(left = bars.left, top = bars.top, right = bars.right, bottom = bars.bottom)
            insets
        }
        permissionRequested = savedInstanceState?.getBoolean("permissionRequested") ?: false
        permissionInFlight = savedInstanceState?.getBoolean("permissionInFlight") ?: false
        binding.updateAction.setOnClickListener {
            when (AppUpdater.state.value) {
                AppUpdater.State.Ready -> requestInstall()
                is AppUpdater.State.NeedsConfirmation -> launchConfirmation()
                else -> {
                    permissionRequested = false
                    AppUpdater.start(this, intent.getStringExtra(EXTRA_URL))
                }
            }
        }
        binding.updateClose.setOnClickListener { close() }
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() = close()
        })
        lifecycleScope.launch {
            // Never launch system UI from a background receiver or a stopped screen.
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                AppUpdater.state.collect { state ->
                    render(state)
                    when (state) {
                        AppUpdater.State.Ready -> {
                            if (canInstall()) AppUpdater.install(this@UpdateActivity)
                            else if (!permissionRequested) requestInstall()
                        }
                        is AppUpdater.State.NeedsConfirmation -> launchConfirmation()
                        else -> Unit
                    }
                }
            }
        }
        // Existing in-process work is retained. After process death start() can
        // reuse the completed APK, including on return from permission settings.
        if (AppUpdater.state.value == AppUpdater.State.Idle)
            AppUpdater.start(this, intent.getStringExtra(EXTRA_URL))
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putBoolean("permissionRequested", permissionRequested)
        outState.putBoolean("permissionInFlight", permissionInFlight)
        super.onSaveInstanceState(outState)
    }

    private fun canInstall() = Build.VERSION.SDK_INT < 26 || packageManager.canRequestPackageInstalls()

    private fun requestInstall() {
        if (canInstall()) {
            AppUpdater.install(this)
            return
        }
        if (permissionInFlight) return
        permissionRequested = true
        permissionInFlight = true
        try {
            permissionLauncher.launch(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName")))
        } catch (_: Exception) {
            permissionInFlight = false
            AppUpdater.reportError(getString(R.string.wgk_update_settings_unavailable))
        }
    }

    private fun launchConfirmation() {
        val state = AppUpdater.state.value as? AppUpdater.State.NeedsConfirmation ?: return
        AppUpdater.confirmationLaunched()
        try {
            confirmationLauncher.launch(state.intent)
        } catch (_: Exception) {
            AppUpdater.reportError(getString(R.string.wgk_update_installer_unavailable))
        }
    }

    private fun close() {
        if (AppUpdater.state.value == AppUpdater.State.Installing ||
            AppUpdater.state.value == AppUpdater.State.Confirming) return
        AppUpdater.cancel(this)
        finish()
    }

    private fun render(state: AppUpdater.State) {
        val busy = state is AppUpdater.State.Downloading || state == AppUpdater.State.Verifying ||
            state == AppUpdater.State.Installing || state == AppUpdater.State.Confirming
        binding.updateProgress.isVisible = busy
        val download = state as? AppUpdater.State.Downloading
        binding.updateProgress.isIndeterminate = download == null || download.total <= 0
        if (download != null && download.total > 0)
            binding.updateProgress.progress = ((download.bytes * 100 / download.total).coerceIn(0, 100)).toInt()
        binding.updateStatus.text = when (state) {
            is AppUpdater.State.Downloading -> {
                val done = Formatter.formatShortFileSize(this, state.bytes)
                if (state.total > 0) getString(R.string.updater_download_progress, done,
                    Formatter.formatShortFileSize(this, state.total), state.bytes * 100.0 / state.total)
                else getString(R.string.updater_download_progress_nototal, done)
            }
            AppUpdater.State.Idle, AppUpdater.State.Verifying -> getString(R.string.wgk_update_verifying)
            AppUpdater.State.Ready -> getString(R.string.wgk_update_permission)
            AppUpdater.State.Installing -> getString(R.string.updater_installing)
            is AppUpdater.State.NeedsConfirmation, AppUpdater.State.Confirming -> getString(R.string.wgk_update_confirm)
            AppUpdater.State.Success -> getString(R.string.wgk_update_success)
            is AppUpdater.State.Failure -> getString(R.string.wgk_update_error, state.message)
        }
        val actionWasVisible = binding.updateAction.isVisible
        binding.updateAction.isVisible = state is AppUpdater.State.Failure || state == AppUpdater.State.Ready ||
            state is AppUpdater.State.NeedsConfirmation
        binding.updateAction.setText(if (state == AppUpdater.State.Ready) R.string.wgk_update_allow
            else if (state is AppUpdater.State.NeedsConfirmation) R.string.wgk_update_install
            else R.string.wgk_update_retry)
        binding.updateClose.setText(if (state is AppUpdater.State.Downloading || state == AppUpdater.State.Verifying)
            android.R.string.cancel else R.string.wgk_update_close)
        binding.updateClose.isEnabled = state != AppUpdater.State.Installing && state != AppUpdater.State.Confirming
        if (!actionWasVisible && binding.updateAction.isVisible) binding.updateAction.requestFocus()
    }

    companion object {
        private const val EXTRA_URL = "download_url"

        fun open(context: Context, downloadUrl: String?) {
            if (BuildConfig.BUILD_TYPE == "googleplay") {
                // This build deliberately omits APK installation permissions.
                val market = Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=${context.packageName}"))
                    .setPackage("com.android.vending")
                try {
                    context.startActivity(market)
                } catch (_: Exception) {
                    try {
                        context.startActivity(Intent(Intent.ACTION_VIEW,
                            Uri.parse("https://play.google.com/store/apps/details?id=${context.packageName}")))
                    } catch (_: Exception) {
                        Toast.makeText(context, R.string.wgk_update_store_unavailable, Toast.LENGTH_LONG).show()
                    }
                }
                return
            }
            context.startActivity(Intent(context, UpdateActivity::class.java).putExtra(EXTRA_URL, downloadUrl))
        }
    }
}
