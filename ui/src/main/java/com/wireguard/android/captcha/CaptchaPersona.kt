package com.wireguard.android.captcha

import android.content.Context
import android.os.Build
import android.util.Log
import android.webkit.WebView
import org.json.JSONObject
import java.io.File
import java.security.SecureRandom

/**
 * Персона — набор признаков, по которым VK связывает попытки в одно устройство:
 * User-Agent, размер окна и browser_fp.
 *
 * Персона описывает только капчу. device_id бескапчевого потока VK Calls здесь
 * жил и был отсюда убран: группы добывают креденшлы параллельно, и общий на всех
 * device_id превращал их в одно устройство, дважды заходящее в один звонок, —
 * VK отвечал на это error_code 10, а он стоит капчи. Заодно добыча креденшлов
 * больше не дёргает [current] и не тратит бюджет попыток впустую.
 *
 * Задача — держать баланс между двумя противоположными сигналами. Отпечаток,
 * меняющийся на каждой попытке, читается как бот, перебирающий личности; вечно
 * стабильный упирается в лимиты VK на одно устройство. Поэтому персона живёт
 * ровно один бюджет: [MAX_ATTEMPTS] попыток решения или [MAX_AGE_MS] по времени,
 * что наступит раньше, — и сгорает досрочно, как только VK её отверг ([burn]).
 *
 * Внутри одной попытки персона неизменна. За неё отвечает [ATTEMPT_WINDOW_MS]:
 * обращения, идущие плотнее этого окна, считаются одной попыткой, поэтому
 * лестница «HTTP авто → слайдер POC → невидимый WebView → видимый диалог» видит
 * одну и ту же персону на всех ступенях. Это и есть кеш, общий для обоих
 * WebView и Go-солвера: все трое читают [current], и на проводе UA, окно и
 * browser_fp совпадают независимо от того, какая ступень сработала.
 *
 * Что НЕ рандомизируется: экран, devicePixelRatio, число ядер, память, языки и
 * client hints. Их видимый диалог отдаёт настоящими — там страница измеряет
 * реальный WebView, — так что подмена только на HTTP-пути создала бы расхождение
 * между ступенями одной и той же попытки. Их поставляет CaptchaFingerprintProbe.
 */
object CaptchaPersona {
    private const val TAG = "WireGuard/CaptchaPersona"
    private const val PREFS = "captcha_persona"
    private const val KEY_PERSONA = "persona"

    // Отпечаток из времён, когда он персистился навсегда. Первая персона
    // наследует его, чтобы у существующих установок личность не сменилась
    // одномоментно на ровном месте; дальше файл больше не используется.
    private const val LEGACY_FP_FILE = "captcha_browser_fp"

    /** Сколько попыток решения переживает одна персона. */
    private const val MAX_ATTEMPTS = 5

    /** Предельный возраст персоны, даже если бюджет попыток не выбран. */
    private const val MAX_AGE_MS = 6L * 60 * 60 * 1000

    /**
     * Обращения плотнее этого окна считаются одной попыткой. Должно с запасом
     * покрывать полную лестницу решения (видимый диалог ждёт пользователя до
     * 120 с) и быть заметно больше TTL кеша профиля на стороне Go, иначе
     * ротация могла бы разорвать попытку пополам.
     */
    private const val ATTEMPT_WINDOW_MS = 3L * 60 * 1000

    private val ANDROID_VERSIONS = arrayOf("12", "13", "14", "15")

    // Chrome на Android отдаёт свёрнутый UA — мажор и три нуля, поэтому билд
    // подделывать нечем и не нужно. Мажор берётся у реального WebView, чтобы UA
    // не расходился с client hints, которые Chromium формирует сам и которые мы
    // из приложения не переопределяем.
    private const val FALLBACK_CHROME_MAJOR = 146

    // Физический размер разметки невидимого WebView. innerWidth/innerHeight
    // страница увидит как это значение, делённое на devicePixelRatio.
    private val LAYOUT_WIDTHS = intArrayOf(356, 358, 360, 362, 364, 366, 368)
    private val LAYOUT_HEIGHTS = intArrayOf(376, 378, 380, 382, 384, 386, 388)

    data class Persona(
        val userAgent: String,
        val layoutWidthPx: Int,
        val layoutHeightPx: Int,
        val browserFp: String,
        val createdAtMs: Long,
        val attempts: Int,
        val lastUsedAtMs: Long,
    )

    private val lock = Any()
    private val random = SecureRandom()

    @Volatile
    private var cached: Persona? = null

    /**
     * Действующая персона. Внутри одной попытки возвращает одно и то же; на
     * первом обращении новой попытки списывает бюджет и при необходимости
     * ротирует.
     */
    fun current(context: Context): Persona {
        val appContext = context.applicationContext
        synchronized(lock) {
            val now = System.currentTimeMillis()
            val existing = cached ?: load(appContext)
            val persona = when {
                existing == null -> mint(appContext, now)
                // Внутри окна — та же попытка, персона не меняется. Отрицательный
                // idle означает, что часы уехали назад: считаем это новой попыткой,
                // а не поводом растянуть окно на неопределённый срок.
                (now - existing.lastUsedAtMs) in 0..ATTEMPT_WINDOW_MS -> existing
                else -> {
                    val attempts = existing.attempts + 1
                    val age = now - existing.createdAtMs
                    if (attempts > MAX_ATTEMPTS || age !in 0..MAX_AGE_MS) {
                        Log.d(TAG, "Бюджет персоны исчерпан (попыток $attempts, возраст ${age / 60_000} мин) — ротация")
                        mint(appContext, now)
                    } else {
                        existing.copy(attempts = attempts)
                    }
                }
            }

            val touched = persona.copy(lastUsedAtMs = now)
            cached = touched
            save(appContext, touched)
            return touched
        }
    }

    /**
     * Сжигает персону: VK её отверг (ERROR_LIMIT, статус BOT, исчерпанная
     * лестница решения), значит дальше она бесполезна независимо от остатка
     * бюджета. Следующая капча получит новую.
     */
    fun burn(context: Context, reason: String) {
        val appContext = context.applicationContext
        synchronized(lock) {
            if (cached == null && load(appContext) == null) return
            Log.i(TAG, "Персона сожжена ($reason) — следующая капча получит новую")
            cached = null
            appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .remove(KEY_PERSONA)
                .apply()
        }
    }

    private fun mint(context: Context, now: Long): Persona {
        val androidVersion = ANDROID_VERSIONS[random.nextInt(ANDROID_VERSIONS.size)]
        val chromeMajor = currentWebViewMajor()
        val persona = Persona(
            userAgent = "Mozilla/5.0 (Linux; Android $androidVersion) AppleWebKit/537.36 " +
                "(KHTML, like Gecko) Chrome/${chromeMajor}.0.0.0 Mobile Safari/537.36",
            layoutWidthPx = LAYOUT_WIDTHS[random.nextInt(LAYOUT_WIDTHS.size)],
            layoutHeightPx = LAYOUT_HEIGHTS[random.nextInt(LAYOUT_HEIGHTS.size)],
            browserFp = adoptLegacyFp(context) ?: randomFp(),
            createdAtMs = now,
            attempts = 1,
            lastUsedAtMs = now,
        )
        Log.d(
            TAG,
            "Новая персона: Android $androidVersion, Chrome/$chromeMajor, " +
                "${persona.layoutWidthPx}x${persona.layoutHeightPx}, fp=${persona.browserFp.take(8)}",
        )
        return persona
    }

    private fun currentWebViewMajor(): Int =
        (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WebView.getCurrentWebViewPackage()
        } else {
            null
        })?.versionName
            ?.substringBefore('.')
            ?.toIntOrNull()
            ?: FALLBACK_CHROME_MAJOR

    private fun randomFp(): String {
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Забирает и удаляет отпечаток, который прошлая версия хранила бессрочно,
     * чтобы первая персона после обновления совпала с тем, что VK уже видел.
     */
    private fun adoptLegacyFp(context: Context): String? {
        val file = File(context.filesDir, LEGACY_FP_FILE)
        val existing = runCatching { if (file.exists()) file.readText().trim() else "" }.getOrDefault("")
        runCatching { if (file.exists()) file.delete() }
        if (existing.length != 32 || !existing.all { it.isDigit() || it in 'a'..'f' }) return null
        Log.d(TAG, "Первая персона унаследовала сохранённый browser_fp")
        return existing
    }

    private fun load(context: Context): Persona? {
        val raw = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_PERSONA, null) ?: return null
        return runCatching {
            val json = JSONObject(raw)
            val persona = Persona(
                userAgent = json.getString("userAgent"),
                layoutWidthPx = json.getInt("layoutWidthPx"),
                layoutHeightPx = json.getInt("layoutHeightPx"),
                browserFp = json.getString("browserFp"),
                createdAtMs = json.getLong("createdAtMs"),
                attempts = json.getInt("attempts"),
                lastUsedAtMs = json.getLong("lastUsedAtMs"),
            )
            if (persona.userAgent.isBlank() || persona.browserFp.length != 32 ||
                persona.layoutWidthPx <= 0 || persona.layoutHeightPx <= 0
            ) {
                null
            } else {
                persona
            }
        }.getOrNull()
    }

    private fun save(context: Context, persona: Persona) {
        val json = JSONObject().apply {
            put("userAgent", persona.userAgent)
            put("layoutWidthPx", persona.layoutWidthPx)
            put("layoutHeightPx", persona.layoutHeightPx)
            put("browserFp", persona.browserFp)
            put("createdAtMs", persona.createdAtMs)
            put("attempts", persona.attempts)
            put("lastUsedAtMs", persona.lastUsedAtMs)
        }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_PERSONA, json.toString())
            .apply()
    }
}
