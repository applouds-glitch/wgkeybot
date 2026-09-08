# VK Captcha: как подключаться, чтобы не быть BOT, и как решать PoW

Сводка по результатам live-диагностики (2026-08): captchaNotRobot.check возвращал
`BOT` на корректно решённом PoW. Bisect-тест доказал, что **сам payload принят
сервером** (hash, решённый нашим кодом, скормили настоящему браузеру — сервер
вернул OK). Значит BOT вызывал транспортный слой и детали формы, а не математика PoW.
Ниже — полный набор требований, после выполнения которого check стабильно
возвращает **OK** (подтверждено дважды подряд probe-инструментом).

Оглавление:

1. Схема captcha-сессии
2. TLS: кастомный ClientHello Chrome 151
3. HTTP/2: порядок заголовков и псевдо-заголовков
4. Персона: согласованность на всех слоях
5. Форма captchaNotRobot: domain, adFp, browser_fp, порядок полей
6. Тайминги и сенсорные/сетевые сэмплы
7. PoW v2: payload, telemetry, tel_hash
8. Инструмент диагностики (captcha-probe)
9. Где что лежит в коде

## 1. Схема captcha-сессии

```
get_anonym_token (login.vk.ru)                 — trigger-фаза, мобильная персона
calls.getAnonymousToken (api.vk.ru)            — ошибка 14 → redirect_uri
GET redirect_uri (id.vk.ru)                    — bootstrap HTML: powInput, difficulty,
                                                 settings, script URL (debug_info)
captchaNotRobot.settings    POST api.vk.ru/method/...?v=5.131
captchaNotRobot.componentDone
  ... окно 5.5–7с (браузер «живёт» на странице) ...
captchaNotRobot.check        — PoW hash + telemetry-ответ → OK/BOT/ERROR_LIMIT
captchaNotRobot.endSession
```

Сессия одноразовая: повторный check с тем же session_token мгновенно даёт
ERROR_LIMIT. Поэтому в продакшне `maxAttempts = 1` на сессию.

## 2. TLS: кастомный ClientHello Chrome 151

Реализация: [vk_tls_clienthello.go](../tunnel/tools/libwg-go/vk_tls_clienthello.go)
(+ `tlsclient.WithRandomTLSExtensionOrder()` в [vk.go](../tunnel/tools/libwg-go/vk.go), `fetchVkCreds`).

Всё выверено по проводу против эталонного дампа реального Chrome 151
(tls.peet.ws/api/all, `/tmp/captcha-cdp/peetws-chrome151.json`):

- **PQ signature schemes впереди**: `0x0904, 0x0905, 0x0906` (ML-DSA) перед
  стандартными ECDSA/PSS/PKCS1. У форк-профиля Chrome_146 их не было — это
  самое заметное отличие старых запросов от реального браузера.
- **Нет расширения 0xca34** (trust anchors): Chrome убрал его после 146-й версии.
- **Ciphers**: как в Chrome_146 форка — после проверки оказалось, что на проводе
  они УЖЕ совпадают с реальным 151 (utls переупорядочивает по своему
  preference-списку).
- **`tlsclient.WithRandomTLSExtensionOrder()`** — обязателен. Реальный Chrome 151
  перемешивает порядок TLS-расширений на каждом новом соединении (проверено
  четырьмя прогонами CDP). Фиксированный порядок = бот. JA4 при этом стабилен:
  его хэш порядко-нечувствителен, так что shuffle безопасен.
- **PSK-резюме**: `UtlsPreSharedKeyExtension` в спеке — иначе у utls нет session
  cache и повторные соединения не шлют `pre_shared_key`, как это делает реальный
  Chrome.
- Эталонный JA4 реального Chrome 151: `t13d1517h2_8daaf6152771_a87ad97598a9`.

Зависимости зафиксированы: `kiper292/tls-client v1.14.1`, `bogdanfinn/utls
v1.7.7-barnius`, `bogdanfinn/fhttp v0.6.8` (поддержка zstd).

## 3. HTTP/2: порядок заголовков и псевдо-заголовков

В [vk_captcha.go](../tunnel/tools/libwg-go/vk_captcha.go):

```go
var captchaHeaderOrder = []string{
    "host", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "user-agent", "accept", "content-type", "origin",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "referer",
    "accept-encoding", "accept-language", "priority", "content-length",
}
var captchaPHeaderOrder = []string{":method", ":authority", ":scheme", ":path"}
```

Старый псевдо-порядок `:method, :path, :authority, :scheme` — один из сигналов,
из-за которых приходил BOT. Оба массива задаются через
`req.Header[fhttp.HeaderOrderKey]` / `req.Header[fhttp.PHeaderOrderKey]` на
**каждом** запросе captcha-фазы (включая fetch debug_info из скрипта).

Bootstrap GET должен выглядеть как навигация браузера:

```
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
```

## 4. Персона: согласованность на всех слоях

Каждый слой должен рассказывать об одном устройстве. Нарушения этой
согласованности — классический бот-сигнал:

- **UA/sec-ch-ua заголовков** и **UA внутри PoW telemetry** — один и тот же.
  Продакшн использует персону Android WebView (реальные метрики устройства через
  JNI `getCaptchaDeviceProfile`), поэтому telemetry UA берётся из
  `androidCaptchaProfile().UserAgent`, а не из trigger-профиля.
- **device JSON** (componentDone) — реальные размеры экрана/DPR/ядра/память
  устройства. Вьюпорт фиксируется **один раз на сессию** (раньше
  `requestComponentDone` вызывал `randomViewport()` повторно и мог разойтись с
  вьюпортом, из которого сгенерирован browser_fp).
- **Нет ключа `webdriver`** в device JSON: реальный Chrome его не шлёт, когда
  `navigator.webdriver` undefined. Явное `"webdriver":false` — лишний след.
- **browser_fp персистентен** (хранится на Android-стороне): свежий fp на каждую
  попытку = бот, крутящий личности. При BOT/ERROR_LIMIT персона сжигается
  (`burnCaptchaPersona`) и следующая капча получает новую.
- Язык: Accept-Language заголовков, `navigator.language` в device JSON и
  remixlang-cookie (VK выставляет по первому запросу) должны совпадать.

## 5. Форма captchaNotRobot: domain, adFp, порядок полей

API-версия: **v=5.131** (была 5.258 — не та, что шлёт страница).

- **domain берётся из query redirect_uri**, а не хардкодится `vk.ru`: свежие
  сессии приходят с `domain=vk.com`, и несовпадение рушит сессию.
- **adFp не пустой**: это `window.rb_sync.id` — те же 16 байт, что browser_fp,
  в base64url (22 символа). Детерминированно выводится из browser_fp:
  `hex.DecodeString(browser_fp) → base64.RawURLEncoding`.
  (`captchaAdFpFromBrowserFp` в vk_captcha.go). Один и тот же во всех вызовах
  сессии.
- Порядок полей формы зафиксирован (`captchaFormFieldOrder`) — у VK он
  неалфавитный, и `net/url.Values.Encode` его искажает.

## 6. Тайминги и сенсорные/сетевые сэмплы

- **Окно componentDone → check: 5.5–7с** (раньше было ~0.5с). Страница-браузер
  «живёт» между этими вызовами; мгновенный check — бот-сигнал.
- **Сэмплы сети привязаны к окну**: браузер снимает показания каждые 200мс
  (sensors_delay), поэтому `connectionRtt`/`connectionDownlink` содержат
  `N = elapsed_ms / 200` одинаковых значений (rtt ≈ 40–100, downlink ≈ 1.6–9.6).
  Случайное число сэмплов, не связанное с окном, — расхождение, которое VK
  проверяет. Реализация: `generateNetworkSamples(n)`.
- **Сенсоры — пустые массивы**: `accelerometer=[]`, `gyroscope=[]`, `motion=[]`,
  `cursor=[]`, `taps=[]`. Эталонный браузер слал именно так, и VK принял с OK.
  Синтетический шум сенсоров — худший сигнал, чем их отсутствие.
- `answer = base64("{}")` — пустой checkbox-клик; сам факт клика представлен
  парой hash/answer.

## 7. PoW v2: payload, telemetry, tel_hash

Формат страницы v2 (обфусцированный inline-солвер, вызов через IIFE-аргументы —
`powInput` в HTML парсится из них, а не из `const powInput = "..."`).

**Сам поиск** (solvePoW в vk_captcha.go):

- nonce с **0** (не с 1);
- перед циклом `sleep 2–5мс`: реальный браузер решил difficulty 2 на nonce 76 за
  `duration_ms=2`; честный малый duration_ms важнее скорости — миллисекунды на
  хэш для тривиальной сложности выдают бота.

**Ответ check (`hash`-поле)**:

```
"v2." + base64(json{
    hash:        sha256(powInput + nonce) hex,
    nonce:       N,
    duration_ms: время от старта (включая sleep),
    telemetry:   {...окружение, см. ниже...},
    tel_hash:    sha256(json.Marshal(telemetry)) hex,
})
```

`tel_hash` считается по каноническому `json.Marshal` telemetry: Go сортирует ключи
мапов — это совпадает с канонизатором страницы (проверено bisect-тестом: наш
hash в теле браузера дал OK).

**Telemetry** (buildPowTelemetry) — проверенные значения:

| Поле | Значение | Комментарий |
|---|---|---|
| frame.parentAccessible | **true** | солвер работает в top-frame |
| match_media.prefersDark | **true** | эталонный браузер был в тёмной теме |
| match_media.prefersLight | **false** | |
| match_media.pointerFine | **false** | coarse pointer |
| plugins.length | 0 / 5 | 0 для Android WebView-персоны (честно), 5 для desktop-эталона |
| globals.hw / globals.mem | из androidCaptchaProfile | должны совпадать с device JSON |
| ua.userAgent | персонный UA | совпадает с заголовками |
| referrer.domain | id.vk.ru | |

## 8. Инструмент диагностики (captcha-probe)

[tunnel/tools/captcha-probe](../tunnel/tools/captcha-probe/) — автономная
реплика captcha-фазы вне приложения (те же запросы, тот же клиент, тот же парсер
и солвер):

```bash
# триггер реальной капчи (get_anonym_token + getAnonymousToken) и дамп redirect_uri
./captcha-probe -link https://vk.ru/call/join/xxxx -out /tmp

# fetch bootstrap по сохранённому redirect_uri + живой check до вердикта
./captcha-probe -uri 'https://...redirect_uri...' -out /tmp

# дамп собственного TLS/HTTP2-отпечатка этого клиента (сверять с tls.peet.ws)
./captcha-probe -tlscheck
```

Сборка под устройство (тот же egress IP, что у приложения):

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o captcha-probe .
adb push captcha-probe /data/local/tmp/ && adb shell /data/local/tmp/captcha-probe ...
```

Эталонный отпечаток реального Chrome 151 снимался через CDP
(скрипты в `/tmp/captcha-cdp/`: `tlscheck2-cdp.mjs`, `tlscheck3-dump.mjs`,
`ja3repeat.mjs`) против `https://tls.peet.ws/api/all`.

Методика проверки регресса: если check снова начнёт отвечать BOT — (1) снять
`-tlscheck` и сверить JA4/extensions с эталоном; (2) повторить bisect-тест
(наш hash + реальный браузер): OK в браузере при BOT у нас = транспорт, а не
payload; (3) сравнить дампы формы с захватом браузера (devtools network).

## 9. Где что лежит в коде

| Что | Где |
|---|---|
| ClientHello Chrome 151 + профиль | [vk_tls_clienthello.go](../tunnel/tools/libwg-go/vk_tls_clienthello.go) |
| Создание клиента (профиль + shuffle) | [vk.go](../tunnel/tools/libwg-go/vk.go) `fetchVkCreds` |
| Порядки заголовков, v=5.131 | [vk_captcha.go](../tunnel/tools/libwg-go/vk_captcha.go) `captchaHeaderOrder`/`captchaPHeaderOrder`/`captchaNotRobotAPIVersion` |
| Bootstrap-запрос | [vk_captcha.go](../tunnel/tools/libwg-go/vk_captcha.go) `fetchCaptchaBootstrap` |
| solvePoW / v2 payload / telemetry | [vk_captcha.go](../tunnel/tools/libwg-go/vk_captcha.go) `solvePoW`/`encodePowResultV2`/`buildPowTelemetry` |
| checkbox-путь (domain/adFp/окно/сэмплы) | [vk_captcha.go](../tunnel/tools/libwg-go/vk_captcha.go) `callCaptchaNotRobot` |
| slider-путь (сессия, вьюпорт, сэмплы) | [slider_captcha.go](../tunnel/tools/libwg-go/slider_captcha.go) `captchaNotRobotSession` |
| adFp из browser_fp | [vk_captcha.go](../tunnel/tools/libwg-go/vk_captcha.go) `captchaAdFpFromBrowserFp` |
| Сетевые сэмплы | [vk_captcha.go](../tunnel/tools/libwg-go/vk_captcha.go) `generateNetworkSamples` |
| Device JSON (без webdriver) | [vk_captcha.go](../tunnel/tools/libwg-go/vk_captcha.go) `buildCaptchaDeviceJSON` |
| Персона устройства + ротация | [vk_captcha.go](../tunnel/tools/libwg-go/vk_captcha.go) `androidCaptchaProfile`/`burnCaptchaPersona` |
| Автономный probe | [tunnel/tools/captcha-probe](../tunnel/tools/captcha-probe/) |
