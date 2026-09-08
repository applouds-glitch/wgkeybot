package com.wireguard.android.updater

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.IntentCompat
import com.wireguard.android.BuildConfig
import com.wireguard.android.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** One update at a time, retained across activity recreation and settings trips. */
object AppUpdater {
    sealed interface State {
        data object Idle : State
        data class Downloading(val bytes: Long = 0, val total: Long = -1) : State
        data object Verifying : State
        data object Ready : State
        data object Installing : State
        data class NeedsConfirmation(val intent: Intent) : State
        data object Confirming : State
        data object Success : State
        data class Failure(val message: String) : State
    }

    private val mutableState = MutableStateFlow<State>(State.Idle)
    val state = mutableState.asStateFlow()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var job: Job? = null
    private var source: String? = null
    private var sessionId = -1
    private val fileLock = Mutex()
    private const val PREFS = "apk_updater"
    private const val SESSION = "session"
    private const val SOURCE = "source"
    private const val ACTION_RESULT = "com.wgkeybot.android.UPDATE_RESULT"

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private fun apk(context: Context) = File(context.cacheDir, "app-update/update.apk")

    fun start(context: Context, url: String?) {
        if (job?.isActive == true || state.value is State.Installing ||
            state.value is State.NeedsConfirmation || state.value is State.Confirming) return
        if (source == url && state.value is State.Ready) return
        val app = context.applicationContext
        if (BuildConfig.BUILD_TYPE == "googleplay" || url == null || !UpdatePolicy.isSecureUrl(url)) {
            mutableState.value = State.Failure(app.getString(R.string.wgk_update_invalid_url))
            return
        }
        source = url
        job = scope.launch {
            try {
                mutableState.value = State.Verifying
                withContext(Dispatchers.IO) {
                    fileLock.withLock {
                        // After process death we cannot recover an installer's confirmation
                        // Intent. Retire our previous session and reuse the verified APK.
                        val oldSession = prefs(app).getInt(SESSION, -1)
                        prefs(app).edit().remove(SESSION).apply()
                        if (oldSession >= 0) runCatching {
                            app.packageManager.packageInstaller.abandonSession(oldSession)
                        }
                        val file = apk(app)
                        if (!file.isFile || prefs(app).getString(SOURCE, null) != url) {
                            file.parentFile!!.mkdirs()
                            file.delete()
                            download(app, url, file)
                        }
                        publish(State.Verifying)
                        try {
                            verifyApk(app, file)
                        } catch (e: Exception) {
                            file.delete()
                            prefs(app).edit().remove(SOURCE).apply()
                            throw e
                        }
                        prefs(app).edit().putString(SOURCE, url).apply()
                    }
                }
                mutableState.value = State.Ready
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                currentCoroutineContext().ensureActive()
                fail(app, e)
            }
        }
    }

    private suspend fun publish(state: State) = withContext(Dispatchers.Main.immediate) {
        // Serialize progress with cancel()/start(). A cancelled blocking read must
        // never overwrite Idle or the state of a subsequent download.
        mutableState.value = state
    }

    private suspend fun download(context: Context, initialUrl: String, destination: File) {
        val partial = File(destination.parentFile, "update.part")
        var url = URL(initialUrl)
        try {
            repeat(6) {
                currentCoroutineContext().ensureActive()
                if (!UpdatePolicy.isSecureUrl(url.toString()))
                    throw IOException(context.getString(R.string.wgk_update_invalid_url))
                val connection = (url.openConnection() as HttpURLConnection).apply {
                    instanceFollowRedirects = false
                    connectTimeout = 15_000
                    readTimeout = 30_000
                    setRequestProperty("Accept-Encoding", "identity")
                }
                try {
                    val code = connection.responseCode
                    if (code in listOf(301, 302, 303, 307, 308)) {
                        val location = connection.getHeaderField("Location")
                            ?: throw IOException("HTTP $code")
                        url = URL(url, location)
                        return@repeat
                    }
                    if (code != HttpURLConnection.HTTP_OK) throw IOException("HTTP $code")
                    val total = connection.contentLengthLong
                    if (total > UpdatePolicy.MAX_APK_BYTES)
                        throw IOException(context.getString(R.string.wgk_update_too_large))
                    publish(State.Downloading(0, total))
                    connection.inputStream.use { input ->
                        partial.outputStream().use { output ->
                            val buffer = ByteArray(64 * 1024)
                            var count = 0L
                            var lastProgress = 0L
                            while (true) {
                                currentCoroutineContext().ensureActive()
                                val read = input.read(buffer)
                                currentCoroutineContext().ensureActive()
                                if (read < 0) break
                                count += read
                                if (count > UpdatePolicy.MAX_APK_BYTES)
                                    throw IOException(context.getString(R.string.wgk_update_too_large))
                                output.write(buffer, 0, read)
                                val now = android.os.SystemClock.elapsedRealtime()
                                if (now - lastProgress >= 150) {
                                    publish(State.Downloading(count, total))
                                    lastProgress = now
                                }
                            }
                            if (count == 0L || (total >= 0 && count != total))
                                throw IOException(context.getString(R.string.wgk_update_incomplete))
                            output.fd.sync()
                        }
                    }
                    if (!partial.renameTo(destination)) throw IOException("Cannot save APK")
                    return
                } finally {
                    connection.disconnect()
                }
            }
            throw IOException(context.getString(R.string.wgk_update_invalid_url))
        } finally {
            partial.delete()
        }
    }

    @Suppress("DEPRECATION")
    private fun verifyApk(context: Context, file: File) {
        val pm = context.packageManager
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES
            else PackageManager.GET_SIGNATURES
        val incoming = pm.getPackageArchiveInfo(file.absolutePath, flags)
            ?: throw IOException(context.getString(R.string.wgk_update_invalid_apk))
        val installed = pm.getPackageInfo(context.packageName, flags)
        if (incoming.packageName != context.packageName)
            throw IOException(context.getString(R.string.wgk_update_wrong_package))
        fun version(info: PackageInfo) = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode
            else info.versionCode.toLong()
        if (version(incoming) <= version(installed))
            throw IOException(context.getString(R.string.wgk_update_old_apk))
        fun signers(info: PackageInfo, history: Boolean = false): Set<String> {
            val signatures = if (Build.VERSION.SDK_INT >= 28) {
                val signing = info.signingInfo ?: return emptySet()
                if (history && !signing.hasMultipleSigners()) signing.signingCertificateHistory
                else signing.apkContentsSigners
            } else info.signatures
            return signatures.orEmpty().map {
                MessageDigest.getInstance("SHA-256").digest(it.toByteArray())
                    .joinToString("") { byte -> "%02x".format(byte) }
            }.toSet()
        }
        if (!UpdatePolicy.compatibleSigners(signers(installed), signers(incoming), signers(incoming, true)))
            throw IOException(context.getString(R.string.wgk_update_wrong_signature))
        // PackageInstaller performs authoritative signature and rotation-capability
        // verification again before replacing the installed application.
    }

    fun install(context: Context) {
        if (state.value != State.Ready) return
        val app = context.applicationContext
        if (Build.VERSION.SDK_INT >= 26 && !app.packageManager.canRequestPackageInstalls()) return
        mutableState.value = State.Installing
        job = scope.launch {
            var createdSession = -1
            try {
                withContext(Dispatchers.IO) {
                    val file = apk(app)
                    verifyApk(app, file)
                    val installer = app.packageManager.packageInstaller
                    val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
                        setAppPackageName(app.packageName)
                        setSize(file.length())
                        if (Build.VERSION.SDK_INT >= 31)
                            setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
                        if (Build.VERSION.SDK_INT >= 33)
                            setPackageSource(PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE)
                    }
                    createdSession = installer.createSession(params)
                    installer.openSession(createdSession).use { session ->
                        file.inputStream().use { input ->
                            session.openWrite("base.apk", 0, file.length()).use { output ->
                                input.copyTo(output)
                                session.fsync(output)
                            }
                        }
                        currentCoroutineContext().ensureActive()
                        // Persist before commit: the receiver can run in a new process.
                        if (!prefs(app).edit().putInt(SESSION, createdSession).commit())
                            throw IOException("Cannot save installation session")
                        sessionId = createdSession
                        val callback = Intent(app, UpdateReceiver::class.java).setAction(ACTION_RESULT)
                        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                            if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
                        val result = PendingIntent.getBroadcast(app, createdSession, callback, flags)
                        session.commit(result.intentSender)
                    }
                }
            } catch (e: Exception) {
                if (createdSession >= 0) {
                    runCatching { app.packageManager.packageInstaller.abandonSession(createdSession) }
                }
                sessionId = -1
                prefs(app).edit().remove(SESSION).apply()
                if (e is CancellationException) throw e
                fail(app, e)
            }
        }
    }

    fun confirmationLaunched() {
        if (state.value is State.NeedsConfirmation) mutableState.value = State.Confirming
    }

    fun confirmationReturned(context: Context) {
        if (state.value != State.Confirming) return
        val app = context.applicationContext
        val id = sessionId
        scope.launch {
            // Older Android installers return RESULT_CANCELED even after the user
            // accepts. The session callback is authoritative; allow it to arrive.
            delay(7_000)
            if (state.value != State.Confirming || sessionId != id) return@launch
            val active = withContext(Dispatchers.IO) {
                runCatching { app.packageManager.packageInstaller.getSessionInfo(id)?.isActive == true }
                    .getOrDefault(true)
            }
            if (state.value != State.Confirming || sessionId != id) return@launch
            if (active) mutableState.value = State.Installing
            else {
                abandon(app)
                mutableState.value = State.Failure(app.getString(R.string.wgk_update_cancelled))
            }
        }
    }

    fun cancel(context: Context) {
        if (state.value is State.Installing || state.value is State.Confirming) return
        job?.cancel()
        abandon(context)
        mutableState.value = State.Idle
    }

    fun reportError(message: String) {
        mutableState.value = State.Failure(message)
    }

    private fun abandon(context: Context) {
        val id = sessionId.takeIf { it >= 0 } ?: prefs(context).getInt(SESSION, -1)
        sessionId = -1
        prefs(context).edit().remove(SESSION).apply()
        if (id >= 0) runCatching { context.packageManager.packageInstaller.abandonSession(id) }
    }

    private fun fail(context: Context, error: Exception) {
        Log.w("AppUpdater", "Update failed", error)
        mutableState.value = State.Failure(error.localizedMessage ?: context.getString(R.string.wgk_update_failed))
    }

    class UpdateReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != ACTION_RESULT) return
            val id = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1)
            if (id < 0 || id != prefs(context).getInt(SESSION, -1)) return
            sessionId = id
            when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
                PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                    val confirmation = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_INTENT, Intent::class.java)
                    mutableState.value = if (confirmation != null) State.NeedsConfirmation(confirmation)
                        else State.Failure(context.getString(R.string.wgk_update_failed))
                }
                PackageInstaller.STATUS_SUCCESS -> {
                    prefs(context).edit().clear().apply()
                    sessionId = -1
                    apk(context).delete()
                    mutableState.value = State.Success
                }
                else -> {
                    Log.w("AppUpdater", "Installer: ${intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)}")
                    abandon(context)
                    mutableState.value = State.Failure(context.getString(R.string.wgk_update_install_failed))
                }
            }
        }
    }
}
