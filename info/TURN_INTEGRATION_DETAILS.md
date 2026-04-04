# Интеграция VK TURN Proxy (Архитектура)

В данном документе описана архитектура интеграции VK TURN Proxy в форк клиента [WireGuard Android](https://git.zx2c4.com/wireguard-android).

## Содержание

1. [Нативный уровень (Go / JNI)](#1-нативный-уровень-go--jni)
2. [Слой конфигурации (Java)](#2-слой-конфигурации-java)
3. [Логика управления и UI (Kotlin)](#3-логика-управления-и-ui-kotlin)
4. [Протокол взаимодействия](#4-протокол-взаимодействия)
5. [Формат метаданных в конфигурации](#5-формат-метаданных-в-конфигурации)
6. [Расширенные настройки TURN](#6-расширенные-настройки-turn)
7. [Хранение настроек](#7-хранение-настроек)
8. [Архитектура запуска TURN](#8-архитектура-запуска-turn)
9. [PhysicalNetworkMonitor](#9-physicalnetworkmonitor)
10. [Режимы получения credentials](#10-режимы-получения-credentials)
11. [VK Auth Flow](#11-vk-auth-flow)
12. [Метрики и диагностика](#12-метрики-и-диагностика)
13. [DNS Resolver](#13-dns-resolver)
14. [Per-Stream Кэширование Credentials](#14-per-stream-кэширование-credentials)

---

## 1. Нативный уровень (Go / JNI)

### `tunnel/tools/libwg-go/jni.c`

- **`wgProtectSocket(int fd)`**: Функция для вызова `VpnService.protect(fd)` через JNI. Позволяет TURN-клиенту выводить трафик за пределы VPN-туннеля.
  - Валидация fd (возвращает -1 при невалидном fd)
  - Логирование результата (SUCCESS/FAILED)
  - **bindSocket()** — привязка сокета к кэшированному Network object для маршрутизации через правильный интерфейс (вызывается только если `current_network_global != NULL`)

- **`wgTurnProxyStart/Stop`**: Экспортированные методы для управления жизненным циклом прокси-сервера.
  - Принимает `networkHandle` (long long) для привязки к конкретному Network
  - Вызывает `update_current_network()` для кэширования Network object перед запуском

- **`wgNotifyNetworkChange()`**: Функция для сброса DNS resolver и HTTP-соединений при переключении сети (WiFi <-> 4G). Обеспечивает быстрое восстановление соединения после смены сетевого интерфейса.

- **`update_current_network()`**: Внутренняя функция для кэширования Network object и NetworkHandle. Используется для `bindSocket()` при защите сокетов. Вызывается из `wgTurnProxyStart()` и сбрасывается в `wgTurnProxyStop()`.

- **Стабилизация ABI**: Использование простых C-типов (`const char *`, `int`, `long long`) для передачи параметров прокси, что устраняет ошибки выравнивания памяти в Go-структурах на разных архитектурах. Параметр `udp` имеет тип `int` для корректной работы JNI.

- **Детальное логирование**: `wgProtectSocket()` логирует валидацию fd, вызов protect() и результат (SUCCESS/FAILED), а также результат bindSocket() с указанием network handle.

### `tunnel/tools/libwg-go/turn-client.go`

- **Session ID Handshake (Multi-Stream Support)**: Клиент генерирует уникальный 16-байтный UUID при каждом запуске туннеля и отправляет его первым пакетом после DTLS рукопожатия в каждом потоке. Это позволяет серверу агрегировать несколько DTLS-сессий в одно стабильное UDP-соединение до WireGuard сервера, решая проблему "Endpoint Thrashing".
  - Session ID (16 байт) + Stream ID (1 байт) = 17 байт handshake
  - Отправка происходит после успешного DTLS handshake

- **Round-Robin Load Balancing**: Реализация Hub-сервера, который поддерживает `n` параллельных DTLS-соединений. Вместо использования одного «липкого» потока, клиент равномерно распределяет исходящие пакеты WireGuard между всеми готовыми (ready) DTLS-соединениями. Это повышает общую пропускную способность и устойчивость к потерям в отдельных потоках.
  - Переменная `lastUsed` циклически переключается между потоками
  - Пакеты направляются в первый доступный ready-поток

- **Интегрированная авторизация VK**: Реализован полный цикл получения токенов (VK Calls -> OK.ru -> TURN credentials) внутри Go.
  - Использование `turnHTTPClient` с protected sockets

- **Кэширование TURN credentials (per-stream)**: Каждый поток (stream) имеет свой собственный кэш credentials. Это повышает изоляцию и стабильность работы при множественных потоках.
  - `StreamCredentialsCache` — отдельный кэш для каждого stream ID
  - `credentialLifetime = 10 минут`, `cacheSafetyMargin = 60 секунд`
  - `maxCacheErrors = 3`, `errorWindow = 10 секунд` (на каждый поток отдельно)
  - Кэш инвалидируется при смене сети через `wgNotifyNetworkChange()` (все кэши)
  - При 3 auth errors за 10 секунд инвалидируется только кэш конкретного потока
  - `credentialsStore` — централизованное хранилище с RWMutex для потокобезопасности

- **Разделение получения и кэширования credentials**:
  - `getVkCreds()` — управляет кэшированием (проверка, чтение, запись)
  - `fetchVkCreds()` — выполняет HTTP-запросы к VK/OK API без блокировки кэша
  - RWMutex позволяет параллельное чтение кэша несколькими горутинами

- **Защита сокетов**: Все исходящие соединения (HTTP, UDP, TCP) используют `Control` функцию с вызовом `wgProtectSocket`.
  - `protectControl()` — обёртка для syscall.RawConn

- **Custom DNS Resolver**: Встроенный резолвер с обходом системных DNS Android (localhost) для обеспечения работоспособности в условиях активного VPN.
  - Каскадный fallback: UDP (53) → DoH (443) → DoT (853)
  - DNS сервер: `77.88.8.8` (Yandex DNS)
  - DoH endpoint: `https://common.dot.dns.yandex.net/dns-query`
  - DoT endpoint: `77.88.8.8:853`
  - `hostCache` с TTL 5 минут для кэширования resolved адресов
  - `protectedResolverMu` мьютекс для потокобезопасной замены
  - Все DNS запросы используют `protectControl()` для защиты сокетов

- **Таймаут DTLS handshake**: Явный 10-секундный таймаут предотвращает зависания при потере пакетов.
  - `dtlsConn.SetDeadline(time.Now().Add(10 * time.Second))`

- **Staggered запуск потоков**: Потоки запускаются с задержкой 200ms для снижения нагрузки на сервер и предотвращения "шторма" подключений.
  - `time.Sleep(200 * time.Millisecond)` между запусками

- **Watchdog реконнекта**: Автоматическое восстановление соединения при отсутствии ответа в течение 30 секунд.
  - Проверка `time.Since(lastRx.Load()) > 30*time.Second` в TX goroutine

- **No DTLS режим**: Опциональный режим работы без DTLS-инкапсуляции для прямого подключения к WireGuard серверу через TURN. Предназначен для отладки или специфичных сетевых условий. Реализован в методе `runNoDTLS()`.
  - Не совместим с прокси-сервером, требующим DTLS handshake и Session ID

- **Метрики для диагностики**: Счётчики ошибок для отслеживания проблем (dtlsTxDropCount, dtlsRxErrorCount, relayTxErrorCount, relayRxErrorCount, noDtlsTxDropCount, noDtlsRxErrorCount).
  - `atomic.Uint64` для потокобезопасности

- **Улучшенная обработка ошибок аутентификации**: Функции `isAuthError()` и `handleAuthError()` для детектирования и обработки устаревших credentials.
  - Детектирование по строкам: "401", "Unauthorized", "authentication", "invalid credential", "stale nonce"

- **Deadline management**: Явные дедлайны для handshake (10с), session ID (5с) и обновления дедлайнов каждые 5с (30с таймаут).
  - Deadline updater goroutine обновляет каждые 5 секунд

- **Connected UDP/TCP abstraction**: Интерфейс `net.PacketConn` для унификации обработки UDP и TCP соединений.
  - `connectedUDPConn` обёртка для UDP
  - `turn.NewSTUNConn()` для TCP

- **Packet Pool**: Оптимизация выделения памяти через `sync.Pool` для буферов пакетов (2048 байт).
  - `packetPool.Get()` / `packetPool.Put()`

---

## 2. Слой конфигурации (Java)

### `tunnel/src/main/java/com/wireguard/config/`

- **`Peer.java`**: Поддержка `extraLines` — списка строк, начинающихся с `#@`. Это позволяет хранить метаданные прокси прямо в `.conf` файле, не нарушая совместимость с другими клиентами.
  - Парсинг в `Peer.parse()`: строки `#@` сохраняются через `builder.addExtraLine()`
  - Сериализация в `toWgQuickConfig()`: extraLines выводятся как есть

- **`Config.java`**: Парсер корректно передаёт комментарии с префиксом `#@` в соответствующие секции.

---

## 3. Логика управления и UI (Kotlin)

### `ui/src/main/java/com/wireguard/android/turn/TurnProxyManager.kt`

- **`TurnSettings`**: Модель данных для настроек прокси (VK Link, Peer, Port, Streams).
  - Данные: `enabled`, `peer`, `vkLink`, `mode`, `streams`, `useUdp`, `localPort`, `turnIp`, `turnPort`, `noDtls`
  - Методы: `toComments()`, `fromComments()`, `validate()`

- **`TurnConfigProcessor`**: Логика инъекции/извлечения настроек из текста конфигурации. Метод `modifyConfigForActiveTurn` динамически подменяет `Endpoint` на `127.0.0.1`, **принудительно устанавливает MTU в 1280**, и **PersistentKeepalive=25** (для DTLS режима) для компенсации оверхеда инкапсуляции и поддержания соединения.
  - `injectTurnSettings()` — добавляет комментарии `#@wgt:` в первый Peer
  - `extractTurnSettings()` — извлекает настройки из комментариев
  - `modifyConfigForActiveTurn()` — модифицирует конфиг для активного TURN:
    - MTU = 1280 (фиксировано)
    - Endpoint = `127.0.0.1:localPort`
    - PersistentKeepalive = 25 (если noDtls=false) или оригинальное (если noDtls=true)

- **`TurnProxyManager`**: Управляет нативным процессом прокси.

  **Синхронизация при запуске:**
  - Вызывает `TurnBackend.waitForVpnServiceRegistered(2000)` для ожидания регистрации JNI
  - После подтверждения JNI запускает `wgTurnProxyStart()` с параметром `networkHandle`
  - Это гарантирует что `VpnService.protect()` будет работать для всех сокетов TURN

  **PhysicalNetworkMonitor:**
  - Отдельный класс `PhysicalNetworkMonitor` отслеживает физические сети (WiFi, Cellular)
  - Игнорирует VPN интерфейсы для избежания обратной связи с собственным туннелем
  - Приоритет выбора: WiFi > Cellular > любая другая сеть с интернетом
  - Debounce 1500ms через Flow для фильтрации быстрых переключений
  - `currentNetwork` — синхронное получение текущего лучшего сети без debounce
  - `bestNetwork` — Flow с debounce 1500ms и distinctUntilChanged

  **Автоматический рестарт:**
  - При смене физического типа сети (WiFi ↔ Cellular) TURN переподключается без участия пользователя
  - Вызывает `wgNotifyNetworkChange()` для сброса DNS/HTTP в Go слое
  - Экспоненциальный backoff при неудачах: 2с → 5с → 15с (при более 5 попытках)
  - Флаг `userInitiatedStop` — не рестартировать, если пользователь явно остановил туннель
  - `operationMutex` — мьютекс для сериализации операций start/stop и предотвращения гонок

  **Логирование:**
  - Встроенный лог через `StringBuilder` с ограничением 128KB
  - Методы: `getLog()`, `clearLog()`, `appendLogLine()`

  **Управление жизненным циклом:**
  - `onTunnelEstablished()` — вызывается после создания туннеля
  - `stopForTunnel()` — остановка с сбросом состояния и VpnService reference
  - `isRunning()` — проверка статуса прокси

### `tunnel/src/main/java/com/wireguard/android/backend/TurnBackend.java`

- **AtomicReference для CompletableFuture**: Атомарная замена `CompletableFuture<VpnService>` через `getAndSet()` предотвращает гонки при быстрой смене состояний сервиса.
  - `vpnServiceFutureRef` — хранит текущий Future
  - `getAndSet(new CompletableFuture<>)` — атомарная замена на новый

- **CountDownLatch для синхронизации JNI**: Latch сигнализирует что JNI зарегистрирован и готов защищать сокеты.
  - `vpnServiceLatchRef` — AtomicReference с CountDownLatch
  - `countDown()` вызывается после `wgSetVpnService()`

- **`waitForVpnServiceRegistered(timeout)`**: Метод для ожидания регистрации JNI перед запуском TURN прокси.
  - `await(timeout, TimeUnit.MILLISECONDS)` на latch
  - Возвращает `true` при успехе, `false` при timeout/interrupt

- **`wgNotifyNetworkChange()`**: Native функция для сброса DNS/HTTP при смене сети.

- **`wgTurnProxyStart(..., networkHandle)`**: Native функция принимает `networkHandle` (long) для привязки сокетов к конкретному Network.
  - Параметры: `peerAddr`, `vklink`, `n`, `useUdp`, `listenAddr`, `turnIp`, `turnPort`, `noDtls`, `networkHandle`

- **`onVpnServiceCreated()`**: Метод регистрации VpnService в JNI.
  - При `service != null`: `wgSetVpnService()` → `latch.countDown()` → `future.complete()`
  - При `service == null`: сброс future и latch для следующего цикла

### `tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java`

- **Правильный порядок инициализации VpnService:**
  1. В `onCreate()` сначала вызывается `TurnBackend.onVpnServiceCreated(this)` для регистрации в JNI
  2. Затем завершается `vpnService.complete(this)` для Java кода
  - Это гарантирует что JNI готов до того как TurnProxyManager получит Future

- **TURN запускается после создания туннеля:**
  - В `setStateInternal()` TURN прокси запускается после `builder.establish()`
  - Это гарантирует что `VpnService.protect()` будет работать для сокетов TURN
  - Логирование: `"Tunnel established, TURN proxy should be started now"`

- **Регистрация VpnService:**
  - `TurnBackend.onVpnServiceCreated()` вызывается в `onCreate()` для регистрации в JNI
  - `onDestroy()` сбрасывает future и latch для следующего цикла

- **Защита сокетов WireGuard:**
  - `service.protect(wgGetSocketV4(currentTunnelHandle))`
  - `service.protect(wgGetSocketV6(currentTunnelHandle))`
  - Вызывается ДО запуска TURN прокси

### `ui/src/main/java/com/wireguard/android/model/TunnelManager.kt`

- **Запуск TURN после создания туннеля:**
  - TURN прокси запускается через `TurnProxyManager.onTunnelEstablished()` после того как `GoBackend.setStateInternal()` завершит создание туннеля

---

## 4. Протокол взаимодействия

Для обеспечения стабильности соединения в условиях мультиплексирования (Multi-Stream) используется следующий протокол:

1. **DTLS Handshake**: Стандартное установление защищенного соединения (с таймаутом 10 секунд).
   - Генерация self-signed сертификата один раз на все потоки
   - Cipher suite: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
   - Connection ID Generator: `OnlySendCIDGenerator()`

2. **Session Identification**: Клиент отправляет 17 байт в DTLS поток:
   - 16 байт — Session ID (UUID, генерируется при каждом запуске)
   - 1 байт — Stream ID (номер потока 0..n-1)
   - Отправка происходит сразу после успешного handshake

3. **Tunnel Traffic**: После отправки Session ID начинается двусторонний обмен пакетами WireGuard.
   - Round-robin распределение по готовым потокам
   - Watchdog 30 секунд на отсутствие RX

Это позволяет прокси-серверу идентифицировать сессию пользователя и поддерживать стабильный `Endpoint` на стороне WireGuard сервера, вне зависимости от количества активных DTLS-потоков или смены IP-адресов клиента.

**No DTLS режим:**
- При `noDtls=true` пропускается DTLS handshake и Session ID handshake
- Прямой relay между WireGuard клиентом и сервером через TURN
- Не совместим с прокси-сервером, требующим Session ID

---

## 5. Формат метаданных в конфигурации

Для хранения настроек используются специально размеченные комментарии в секции `[Peer]`:

```ini
[Peer]
PublicKey = <key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0

# [Peer] TURN extensions
#@wgt:EnableTURN = true
#@wgt:UseUDP = false
#@wgt:IPPort = 1.2.3.4:56000
#@wgt:VKLink = https://vk.com/call/join/...
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:TurnIP = 1.2.3.4        # (optional) Override TURN server IP
#@wgt:TurnPort = 12345        # (optional) Override TURN server port
#@wgt:NoDTLS = true           # (optional) Disable DTLS obfuscation
```

Эти строки игнорируются стандартными клиентами WireGuard, но считываются данным форком при загрузке.

**Обработка extraLines:**
- Строки начинающиеся с `#@` сохраняются в `Peer.extraLines`
- `TurnConfigProcessor.injectTurnSettings()` добавляет комментарии с префиксом `#@wgt:`
- `TurnConfigProcessor.extractTurnSettings()` извлекает настройки из комментариев
- При сериализации в `toWgQuickConfig()` extraLines выводятся как есть

---

## 6. Расширенные настройки TURN

### TurnIP и TurnPort

Позволяют переопределить адрес TURN сервера, полученный из VK/OK API. Полезно для:
- Подключения к конкретному серверу TURN
- Обхода проблем с маршрутизацией
- Тестирования инфраструктуры

**Пример:**
```
#@wgt:TurnIP = 155.212.199.166
#@wgt:TurnPort = 19302
```

**Логика применения (turn-client.go):**
- Если `turnIp != ""` и `turnPort != 0`: адрес = `turnIp:turnPort`
- Если `turnIp != ""` и `turnPort == 0`: порт берётся из оригинального адреса
- Если `turnIp == ""` и `turnPort != 0`: хост берётся из оригинального адреса

### No DTLS

Отключает DTLS-инкапсуляцию трафика WireGuard. Предназначен для:
- Отладки соединения
- Прямого подключения к WireGuard серверу через TURN
- Сценариев, где DTLS не требуется

**Важно:** Режим No DTLS несовместим с нашим прокси-сервером, который требует DTLS handshake и Session ID. Используйте только для прямого подключения к WireGuard серверу.

**Пример:**
```
#@wgt:NoDTLS = true
```

### PersistentKeepalive (автоматический)

При включённом DTLS режиме (`#@wgt:NoDTLS = false` или не указано), `TurnConfigProcessor.modifyConfigForActiveTurn` **автоматически устанавливает PersistentKeepalive=25** для всех пиров.

**Назначение:**
- Поддержание NAT mapping для DTLS соединения
- Предотвращение таймаута UDP сессии на стороне TURN сервера
- Значение 25 секунд выбрано как оптимальный баланс между нагрузкой и надёжностью

**Логика:**
- Если в конфиге уже указан PersistentKeepalive ≤ 25, используется оригинальное значение
- Если PersistentKeepalive не указан или > 25, устанавливается 25
- В режиме No DTLS PersistentKeepalive не модифицируется

**Пример (автоматически добавляется):**
```
[Peer]
PublicKey = <key>
Endpoint = 127.0.0.1:9000
PersistentKeepalive = 25
```

---

## 7. Хранение настроек

### TurnSettingsStore

Настройки TURN сохраняются в отдельном JSON-файле `<tunnel>.turn.json` в директории приложения. Это позволяет:
- Хранить настройки независимо от конфига
- Обновлять конфиг без потери настроек TURN
- Быстро загружать/применять настройки

**Формат файла:**
```json
{
  "enabled": true,
  "peer": "89.250.227.41:56000",
  "vkLink": "https://vk.com/call/join/...",
  "streams": 4,
  "useUdp": false,
  "localPort": 9000,
  "turnIp": "",
  "turnPort": 0,
  "noDtls": false
}
```

**Методы TurnSettingsStore:**
- `load(name: String)` — загрузка из JSON файла
- `save(name: String, settings: TurnSettings?)` — сохранение в JSON файл
- `delete(name: String)` — удаление файла настроек
- `rename(name: String, replacement: String)` — переименование файла

**Расположение файлов:**
- Путь: `<context.filesDir>/<tunnel>.turn.json`
- Пример: `/data/data/com.wireguard.android/files/mytunnel.turn.json`

---

## 8. Архитектура запуска TURN

```
GoBackend.setStateInternal()
  → builder.establish()                    ← Туннель создан
  → wgTurnOn()                             ← Go backend запущен
  → service.protect() для сокетов WireGuard
  → TurnProxyManager.onTunnelEstablished() ← TURN запускается ПОСЛЕ туннеля
    → PhysicalNetworkMonitor.currentNetwork ← Получение текущего network handle
    → TurnBackend.waitForVpnServiceRegistered() ← Ждём JNI
    → wgTurnProxyStart(..., networkHandle) ← Запуск TURN с handle сети
      → update_current_network() в JNI      ← Кэширование Network object
      → wgNotifyNetworkChange()             ← Инициализация resolver и HTTP client
      → VK Auth для получения credentials
      → Подключение к TURN серверу (4 потока)
      → DTLS handshake для каждого потока  ← 10с таймаут
      → Session ID handshake (17 байт)     ← UUID + Stream ID
      → wgProtectSocket() + bindSocket() для всех сокетов
```

**Преимущества:**
- TURN запускается после создания туннеля, что гарантирует работу `VpnService.protect()` для всех сокетов
- Явная синхронизация через CountDownLatch исключает гонки условий
- Сокеты WireGuard защищаются до запуска TURN
- **networkHandle** передаётся в Go для привязки сокетов к конкретному Network через `bindSocket()`
- **PhysicalNetworkMonitor** отслеживает физические сети и автоматически перезапускает TURN при смене типа сети

**Временные параметры:**
- Timeout ожидания JNI: 2000ms
- Задержка между запусками потоков: 200ms
- Timeout DTLS handshake: 10s
- Timeout ожидания ready потока: 30s
- Watchdog реконнекта: 30s
- Debounce network change: 1500ms

---

## 9. PhysicalNetworkMonitor

### Расположение
`ui/src/main/java/com/wireguard/android/turn/PhysicalNetworkMonitor.kt`

### Назначение
Мониторинг физических сетей (WiFi, Cellular) для автоматического перезапуска TURN при смене типа подключения.

### Ключевые особенности

**Приоритет сетей:**
1. WiFi (TRANSPORT_WIFI)
2. Cellular (TRANSPORT_CELLULAR)
3. Любая другая физическая сеть с интернетом

**Фильтрация:**
- Игнорирует VPN транспорты (`TRANSPORT_VPN`) — предотвращает обратную связь с собственным туннелем
- Требует `NET_CAPABILITY_INTERNET` — только сети с доступом в интернет
- Требует `NET_CAPABILITY_NOT_VPN` — исключает VPN из рассмотрения

**Debounce и стабильность:**
- `bestNetwork` Flow с debounce **1500ms** — фильтрация быстрых переключений
- `distinctUntilChanged()` — только уникальные изменения
- `currentNetwork` — синхронное получение текущего значения без debounce

**NetworkCallback:**
- `onCapabilitiesChanged()` — синхронизация capabilities, добавление/удаление из ConcurrentHashMap
- `onLost()` — удаление сети из мониторинга
- `update()` — применение логики приоритетов и обновление `_bestNetwork`

**Жизненный цикл:**
- `start()` — регистрация callback, инициализация текущего состояния
- `stop()` — отписка callback, очистка ConcurrentHashMap

### Интеграция с TurnProxyManager

```kotlin
val networkMonitor = PhysicalNetworkMonitor(context)
networkMonitor.start()

scope.launch {
    networkMonitor.bestNetwork.collectLatest { network ->
        if (network != null) {
            handleNetworkChange(network)
        }
    }
}
```

**Логика рестарта:**
1. Сохранение baseline сети при запуске туннеля
2. Игнорирование одинаковых сетей (стабильность)
3. При реальном изменении — вызов `performRestartSequence()`
4. Рестарт: stop → wgNotifyNetworkChange() → delay(500) → start

### Преимущества

- **Централизованный мониторинг** — отдельный класс для отслеживания физических сетей
- **Приоритизация** — явный выбор WiFi > Cellular
- **Flow-based** — реактивный подход с debounce через Kotlin Flow
- **Игнорирование VPN** — явная фильтрация VPN транспортов
- **ConcurrentHashMap** — потокобезопасное хранение сетей

**Технические детали:**
- `networks: ConcurrentHashMap<Network, NetworkCapabilities>` — хранение всех доступных сетей
- `callback: ConnectivityManager.NetworkCallback` — системный callback для событий сети
- `request: NetworkRequest` — запрос с `NET_CAPABILITY_INTERNET` и `NET_CAPABILITY_NOT_VPN`
- `cm.allNetworks.forEach` — начальное заполнение при `start()`

---

## 10. Режимы получения credentials

### Обзор

TURN клиент поддерживает два режима получения TURN credentials, выбираемых через UI:

| Параметр | VK Link | WB |
|----------|---------|-----|
| **Описание** | Получение кредов через VK/OK API | Получение кредов через WB Stream (LiveKit ICE) |
| **Требует vkLink** | Да (ссылка на VK call) | Нет |
| **Протокол** | HTTP API VK/OK | WebSocket + LiveKit ICE |
| **Файл** | `vk.go` | `wb.go` |

### UI выбор режима

В редакторе туннеля (TunnelEditorFragment) добавлен **Spinner** для выбора режима:
- **VK Link** — отображается поле для ввода VK Calls link
- **WB** — поле VK Link скрыто (не требуется)

В режиме просмотра (TunnelDetailFragment) отображается текущий режим и скрывается VK Link для режима WB.

### Режим VK Link

При `mode = "vk_link"`:
1. Пользователь вводит ссылку на VK call (например `https://vk.ru/call/join/...`)
2. `getVkCreds()` выполняет цепочку API вызовов:
   - Token 1: `login.vk.ru/?act=get_anonym_token` (messages anonym_token)
   - getCallPreview: `api.vk.ru/method/calls.getCallPreview`
   - Token 2: `api.vk.ru/method/calls.getAnonymousToken`
   - Token 3: `calls.okcdn.ru/fb.do` (auth.anonymLogin)
   - Token 4: `calls.okcdn.ru/fb.do` (vchat.joinConversationByLink → TURN credentials)
3. Полученные credentials (username, password, serverAddr) кэшируются на 10 минут

**Файл:** `tunnel/tools/libwg-go/vk.go`

### Режим WB (Wildberries)

При `mode = "wb"`:
1. `wbFetch()` не требует vkLink (параметр игнорируется)
2. Выполняется полный цикл WB Stream:
   - Guest register: `/auth/api/v1/auth/user/guest-register`
   - Create room: `/api-room/api/v2/room`
   - Join room: `/api-room/api/v1/room/{roomId}/join`
   - Get room token: `/api-room-manager/api/v1/room/{roomId}/token`
   - LiveKit ICE: WebSocket `wss://wbstream01-el.wb.ru:7880/rtc` → парсинг protobuf → TURN credentials
3. Полученные credentials кэшируются на 10 минут

**Файл:** `tunnel/tools/libwg-go/wb.go`

### Архитектура выбора режима

**Go backend (`turn-client.go`):**
```go
var globalGetCreds getCredsFunc  // Глобальная функция для получения кредов

func wgTurnProxyStart(..., modeC *C.char, ...) int32 {
    mode := C.GoString(modeC)
    
    if mode == "wb" {
        globalGetCreds = func(ctx, link, streamID) {
            return getCredsCached(ctx, link, streamID, wbFetch)
        }
    } else {
        globalGetCreds = func(ctx, lk, streamID) {
            return getCredsCached(ctx, lk, streamID, func(ctx, l) {
                return getVkCreds(ctx, l, streamID)
            })
        }
    }
}
```

**Stream.run()** использует `globalGetCreds` вместо жёсткого вызова `getVkCreds`:
```go
func (s *stream) run(link string, ...) {
    user, pass, addr, err := globalGetCreds(sCtx, link, s.id)
    // ...
}
```

### Разделение файлов Go backend

Для лучшей организации кода `turn-credentials.go` разделён на три файла:

| Файл | Содержимое |
|------|------------|
| `credentials.go` | Общие типы (`TurnCredentials`, `StreamCredentialsCache`), кэширование (`getCredsCached`, `serializeFetch`), `fetchMu`, константы |
| `vk.go` | VK-специфичная логика (`VKCredentials`, `getVkCreds`, `fetchVkCreds`, `getTokenChain`, `vkDelayRandom`) |
| `wb.go` | WB-специфичная логика (`WbTurnCred`, `wbFetch`, `fetchWbCreds`, `wbLkICE`, протобуф-парсеры `wbPbVar`, `wbPbAll`, `wbPbStr`, `wbPbICE`, `wbDedup`) |

### Формат хранения режима

Режим сохраняется в конфиге WireGuard:
```
#@wgt:Mode = vk_link
```
или
```
#@wgt:Mode = wb
```

А также в JSON файле настроек `<tunnel>.turn.json`:
```json
{
  "enabled": true,
  "peer": "89.250.227.41:56000",
  "vkLink": "https://vk.com/call/join/...",
  "mode": "vk_link",
  "streams": 4,
  "useUdp": false,
  "localPort": 9000
}
```

---

## 11. VK Auth Flow

### Кэширование credentials

**Краткая информация:**

- Каждый поток имеет свой собственный кэш credentials (per-stream)
- TTL: 10 минут, safety margin: 60 секунд
- При 3 auth errors за 10 секунд инвалидируется только кэш конкретного потока
- При смене сети инвалидируются все кэши

**Подробная информация:** См. раздел [13. Per-Stream Кэширование Credentials](#13-per-stream-кэширование-credentials)

### Обработка ошибок аутентификации

**Детектирование auth error:**
- Строки в ошибке: "401", "Unauthorized", "authentication", "invalid credential", "stale nonce"
- Функция `isAuthError(err)` проверяет текст ошибки

**Логика:**
- Счётчик ошибок на каждый поток отдельно (sliding window 10 секунд)
- При 3 ошибках: инвалидация кэша только этого потока
- Логи: `[STREAM X] Auth error (count=N/3)`

---

## 11. Метрики и диагностика

### Счётчики ошибок (atomic.Uint64/atomic.Int32)

- `dtlsTxDropCount` (atomic.Uint64) — пакеты, отброшенные в DTLS TX goroutine
- `dtlsRxErrorCount` (atomic.Uint64) — ошибки в DTLS RX goroutine
- `relayTxErrorCount` (atomic.Uint64) — ошибки записи в relay connection
- `relayRxErrorCount` (atomic.Uint64) — ошибки чтения из relay connection
- `noDtlsTxDropCount` (atomic.Uint64) — пакеты, отброшенные в NoDTLS режиме
- `noDtlsRxErrorCount` (atomic.Uint64) — ошибки в NoDTLS RX goroutine

**Per-stream счётчики (в StreamCredentialsCache):**
- `errorCount` (atomic.Int32) — счётчик auth ошибок для конкретного потока (сбрасывается при успехе или после 10 секунд)
- `lastErrorTime` (atomic.Int64) — время последней auth ошибки для sliding window (на каждый поток)

### Логирование

**Уровни логирования:**
- `ANDROID_LOG_INFO` — успешные операции (handshake SUCCESS, protect SUCCESS)
- `ANDROID_LOG_ERROR` — ошибки (protect FAILED, auth errors, timeouts)
- `ANDROID_LOG_WARN` — предупреждения (например, network not found)

**Основные теги:**
- `WireGuard/TurnClient` — основное логирование TURN клиента (Go)
- `WireGuard/TurnProxyManager` — логирование на уровне Kotlin (TurnProxyManager)
- `WireGuard/TurnBackend` — JNI слой (Java)
- `WireGuard/GoBackend` — Go backend
- `WireGuard/JNI` — JNI функции (защита сокетов, bindSocket)
- `WireGuard/TurnSettingsStore` — хранение настроек TURN
- `WireGuard/DNS` — DNS resolver (кэширование, запросы)

**Формат логов:**
```
[PROXY] Hub starting on 127.0.0.1:9000 (streams=4, noDtls=false, networkHandle=12345)
[VK Auth] Using cached credentials (expires in 5m30s)
[STREAM 0] Dialing TURN server 1.2.3.4:56000...
[STREAM 0] DTLS handshake SUCCESS
[STREAM 0] TX watchdog timeout
[NETWORK] Network change notified: resolver reset
[DNS] UDP success: vpn.example.com -> 192.168.1.100
[JNI] wgProtectSocket(fd=123): SUCCESS (protected + bound to net 72057594037927936)
```

---

## 12. DNS Resolver

### Расположение
`tunnel/tools/libwg-go/turn-dns-resolver.go`

### Назначение
Обход системных DNS Android (которые могут не работать через VPN) для разрешения доменных имён TURN серверов и API endpoints.

### Архитектура

**Каскадный fallback:**
1. **UDP (порт 53)** — стандартный DNS запрос, самый быстрый
2. **DoH (порт 443)** — DNS-over-HTTPS, fallback если UDP заблокирован
3. **DoT (порт 853)** — DNS-over-TLS, последний fallback

**Серверы:**
- DNS сервер: `77.88.8.8` (Yandex DNS)
- DoH: `https://common.dot.dns.yandex.net/dns-query` (`77.88.8.8:443`)
- DoT: `77.88.8.8:853` (ServerName: `common.dot.dns.yandex.net`)

### DnsCache

**Параметры:**
- `cacheTTL = 5 минут` — время жизни записи в кэше
- `dnsTimeout = 2 секунды` — таймаут для UDP DNS
- `dohTimeout = 5 секунд` — таймаут для DoH
- `dotTimeout = 5 секунд` — таймаут для DoT

**Методы:**
- `Resolve(ctx, domain)` — разрешение домена с кэшированием
- `ClearCache()` — очистка кэша (вызывается при смене сети)

### Интеграция

**VK Auth Flow:**
- Все HTTP запросы к VK API используют `hostCache.Resolve()` для разрешения доменов
- DNS resolution происходит перед каждым запросом при отсутствии в кэше
- TURN server address resolution в `getVkCreds()` после получения credentials

**Логирование:**
```
[DNS] Trying UDP for api.vk.ru
[DNS] UDP success: api.vk.ru -> 93.186.234.10
[TURN DNS] Resolved TURN server relay.example.com -> 155.212.199.166
[DNS] Cache cleared
```

### Защита сокетов

Все DNS запросы используют `protectControl()` для защиты сокетов через `VpnService.protect()`:
- UDP dialer с `Control: protectControl`
- DoH/DoT dialer с `protectAndDial()`

Это гарантирует что DNS трафик обходит VPN туннель и идёт через физический интерфейс.

### Особенности реализации

**DNS query format:**
- A record запрос (TYPE=1, CLASS=IN)
- Random ID для каждого запроса
- Стандартный рекурсивный запрос

**DoH:**
- HTTP/2 приоритет (per RFC 8484)
- Content-Type: `application/dns-message`
- Accept: `application/dns-message`

**DoT:**
- 2-byte length prefix перед DNS query
- TLS handshake с явным ServerName
- Минимальная версия TLS 1.2

---

## 13. Per-Stream Кэширование Credentials

### Архитектура

**Структуры данных:**

```go
// StreamCredentialsCache — кэш одного потока
type StreamCredentialsCache struct {
    creds         TurnCredentials      // Username, Password, ServerAddr, ExpiresAt, Link
    mutex         sync.RWMutex         // Защита кэша
    errorCount    atomic.Int32         // Счётчик auth ошибок
    lastErrorTime atomic.Int64         // Время последней ошибки
}

// credentialsStore — хранилище всех кэшей
var credentialsStore = struct {
    mu     sync.RWMutex
    caches map[int]*StreamCredentialsCache  // streamID -> cache
}{
    caches: make(map[int]*StreamCredentialsCache),
}
```

**Диаграмма потокобезопасности:**

```
credentialsStore (RWMutex)
├── StreamCredentialsCache[0] (RWMutex)
│   ├── creds
│   ├── errorCount (atomic)
│   └── lastErrorTime (atomic)
├── StreamCredentialsCache[1] (RWMutex)
└── StreamCredentialsCache[2] (RWMutex)
```

### Функции

**`getStreamCache(streamID int) *StreamCredentialsCache`**:
- Возвращает существующий кэш или создаёт новый
- Использует double-check locking для потокобезопасности
- Сначала RLock для быстрого пути (чтение)
- При отсутствии — Lock и повторная проверка

**`getVkCreds(ctx, link, streamID)`**:
1. `getStreamCache(streamID)` — получение кэша
2. `RLock()` — проверка валидности credentials
3. Если кэш валиден — возврат из кэша
4. Если кэш невалиден — `fetchVkCreds()` без блокировки
5. `Lock()` — запись новых credentials в кэш

**`fetchVkCreds(ctx, link, streamID)`**:
- HTTP-запросы к VK API и OK.ru
- Разрешение доменов через `hostCache.Resolve()`
- Возвращает username, password, serverAddr

**`handleAuthError(streamID int)`**:
- Инкремент счётчика ошибок для потока
- Проверка sliding window (10 секунд)
- При 3 ошибках — вызов `cache.invalidate(streamID)`

**`invalidate(streamID int)`**:
- Очистка credentials кэша
- Сброс счётчика ошибок и таймера
- Логирование с указанием streamID

**`invalidateAllCaches()`**:
- Инвалидация всех кэшей (при смене сети)
- Очистка map для освобождения памяти
- Логирование для каждого потока

### Сценарии использования

**Нормальная работа:**
1. Поток 0 запрашивает credentials — кэш пуст — fetchVkCreds() — запись в кэш
2. Поток 1 запрашивает credentials — кэш пуст — fetchVkCreds() — запись в кэш (параллельно)
3. Поток 0 reconnect — кэш валиден — возврат из кэша (быстро)
4. Поток 1 reconnect — кэш валиден — возврат из кэша (быстро)

**Auth ошибка на одном потоке:**
1. Поток 0: ошибка 1 — счётчик = 1
2. Поток 1: кэш валиден — работает нормально
3. Поток 0: ошибка 2 — счётчик = 2
4. Поток 0: ошибка 3 — инвалидация кэша потока 0
5. Поток 0: следующий reconnect — fetchVkCreds() — новый кэш
6. Поток 1: продолжает использовать свой кэш

**Смена сети:**
1. `wgNotifyNetworkChange()` вызван
2. `invalidateAllCaches()` — все кэши инвалидируются
3. `ClearCache()` — очистка DNS кэша
4. Все потоки выполняют fetchVkCreds() при следующем reconnect

### Преимущества

- **Изоляция**: Ошибка на одном потоке не влияет на другие
- **Параллелизм**: RWMutex позволяет concurrent read
- **Производительность**: HTTP-запросы без блокировки кэша
- **Память**: Максимум 16 кэшей × ~100 байт = ~1.6 КБ
