# Интеграция VK TURN Proxy (Архитектура)

В данном документе описана архитектура интеграции VK TURN Proxy в форк клиента [WireGuard Android](https://git.zx2c4.com/wireguard-android).

## 1. Нативный уровень (Go / JNI)

### `tunnel/tools/libwg-go/jni.c`

- **`wgProtectSocket(int fd)`**: Функция для вызова `VpnService.protect(fd)` через JNI. Позволяет TURN-клиенту выводить трафик за пределы VPN-туннеля.
- **`wgTurnProxyStart/Stop`**: Экспортированные методы для управления жизненным циклом прокси-сервера.
- **`wgNotifyNetworkChange()`**: Функция для сброса DNS resolver и HTTP-соединений при переключении сети (WiFi <-> 4G). Обеспечивает быстрое восстановление соединения после смены сетевого интерфейса.
- **Стабилизация ABI**: Использование простых C-типов (`const char *`, `int`) для передачи параметров прокси, что устраняет ошибки выравнивания памяти в Go-структурах на разных архитектурах. Параметр `udp` изменён с `boolean` на `int` для корректной работы JNI.
- **Детальное логирование**: `wgProtectSocket()` логирует валидацию fd, вызов protect() и результат (SUCCESS/FAILED).

### `tunnel/tools/libwg-go/turn-client.go`

- **Session ID Handshake (Multi-User Support)**: Клиент генерирует уникальный 16-байтный UUID при каждом запуске туннеля и отправляет его первым пакетом после DTLS рукопожатия в каждом потоке. Это позволяет серверу агрегировать несколько DTLS-сессий в одно стабильное UDP-соединение до WireGuard сервера, решая проблему "Endpoint Thrashing".
- **Round-Robin Load Balancing**: Реализация Hub-сервера, который поддерживает `n` параллельных DTLS-соединений. Вместо использования одного «липкого» потока, клиент равномерно распределяет исходящие пакеты WireGuard между всеми готовыми (ready) DTLS-соединениями. Это повышает общую пропускную способность и устойчивость к потерям в отдельных потоках.
- **Интегрированная авторизация VK**: Реализован полный цикл получения токенов (VK Calls -> OK.ru -> TURN credentials) внутри Go.
- **Кэширование TURN credentials**: Credentials кэшируются на 9 минут (10 минут TTL - 1 минута запас). При реконнекте потоков используются кэшированные данные, что устраняет дублирующие запросы к VK API. Кэш инвалидируется при смене сети через `wgNotifyNetworkChange()`.
- **Защита сокетов**: Все исходящие соединения (HTTP, UDP, TCP) используют `Control` функцию с вызовом `wgProtectSocket`.
- **Custom DNS Resolver**: Встроенный резолвер с обходом системных DNS Android (localhost) для обеспечения работоспособности в условиях активного VPN.
- **Таймаут DTLS handshake**: Явный 10-секундный таймаут предотвращает зависания при потере пакетов.
- **Staggered запуск потоков**: Потоки запускаются с задержкой 200ms для снижения нагрузки на сервер и предотвращения "шторма" подключений.
- **Watchdog реконнекта**: Автоматическое восстановление соединения при отсутствии ответа в течение 30 секунд.
- **No DTLS режим**: Опциональный режим работы без DTLS-инкапсуляции для прямого подключения к WireGuard серверу через TURN. Предназначен для отладки или специфичных сетевых условий. Реализован в методе `runNoDTLS()`.

---

## 2. Слой конфигурации (Java)

### `tunnel/src/main/java/com/wireguard/config/`

- **`Peer.java`**: Поддержка `extraLines` — списка строк, начинающихся с `#@`. Это позволяет хранить метаданные прокси прямо в `.conf` файле, не нарушая совместимость с другими клиентами.
- **`Config.java`**: Парсер обновлён для корректной передачи комментариев с префиксом `#@` в соответствующие секции.

---

## 3. Логика управления и UI (Kotlin)

### `ui/src/main/java/com/wireguard/android/turn/TurnProxyManager.kt`

- **`TurnSettings`**: Модель данных для настроек прокси (VK Link, Peer, Port, Streams).
- **`TurnConfigProcessor`**: Логика инъекции/извлечения настроек из текста конфигурации. Метод `modifyConfigForActiveTurn` динамически подменяет `Endpoint` на `127.0.0.1` и **принудительно устанавливает MTU в 1280**, чтобы компенсировать оверхед инкапсуляции.
- **`TurnProxyManager`**: Управляет нативным процессом прокси.

  **Синхронизация при запуске:**
  - Вызывает `TurnBackend.waitForVpnServiceRegistered(2000)` для ожидания регистрации JNI
  - После подтверждения JNI запускает `wgTurnProxyStart()`
  - Это гарантирует что `VpnService.protect()` будет работать для всех сокетов TURN

  **NetworkCallback с фильтрацией (Android 14 fix):**
  - Фильтрация по типу транспорта (WiFi, Cellular, Ethernet) — игнорируются изменения внутри одного типа сети
  - Фильтрация по `NET_CAPABILITY_INTERNET` — игнорируются сети без доступа в интернет
  - Фильтрация по `NET_CAPABILITY_NOT_DEFAULT` — игнорируются фоновые сети (MMS, IMS, VPN)
  - Debounce 15 секунд между рестартами для защиты от «флаппинга» сети
  - Детальное логирование с указанием типа транспорта
  - Флаг `ignoreFirstNetworkChange` — игнорирует первое событие network change после запуска TURN
  - Сброс `lastTransportType = null` в `onLost()` — обеспечивает детектирование следующего переключения сети

  **Автоматический рестарт:**
  - При смене типа сети (WiFi ↔ Cellular) TURN переподключается без участия пользователя
  - Вызывает `wgNotifyNetworkChange()` для сброса DNS/HTTP в Go слое
  - Экспоненциальный backoff при неудачах (5с → 10с → 20с)
  - Флаг `userInitiatedStop` — не рестартировать, если пользователь явно остановил туннель

### `tunnel/src/main/java/com/wireguard/android/backend/TurnBackend.java`

- **AtomicReference для CompletableFuture**: Атомарная замена `CompletableFuture<VpnService>` через `getAndSet()` предотвращает гонки при быстрой смене состояний сервиса.
- **CountDownLatch для синхронизации JNI**: Latch сигнализирует что JNI зарегистрирован и готов защищать сокеты.
- **`waitForVpnServiceRegistered(timeout)`**: Метод для ожидания регистрации JNI перед запуском TURN прокси.
- **`wgNotifyNetworkChange()`**: Native функция для сброса DNS/HTTP при смене сети.

### `tunnel/src/main/java/com/wireguard/android/backend/GoBackend.java`

- **Правильный порядок инициализации VpnService:**
  1. В `onCreate()` сначала вызывается `TurnBackend.onVpnServiceCreated(this)` для регистрации в JNI
  2. Затем завершается `vpnService.complete(this)` для Java кода
  - Это гарантирует что JNI готов до того как TurnProxyManager получит Future

- **TURN запускается после создания туннеля:**
  - В `setStateInternal()` TURN прокси запускается после `builder.establish()`
  - Это гарантирует что `VpnService.protect()` будет работать для сокетов TURN

- **Убрано дублирование:**
  - `TurnBackend.onVpnServiceCreated()` вызывается только в `onCreate()`
  - В `onStartCommand()` вызов удалён

### `ui/src/main/java/com/wireguard/android/model/TunnelManager.kt`

- **Запуск TURN после создания туннеля:**
  - TURN прокси запускается через `TurnProxyManager.onTunnelEstablished()` после того как `GoBackend.setStateInternal()` завершит создание туннеля
  - Метод `startForTunnel()` больше не вызывается до создания туннеля

---

## 4. Протокол взаимодействия

Для обеспечения стабильности соединения в условиях мультиплексирования (Multi-Stream) используется следующий протокол:

1. **DTLS Handshake**: Стандартное установление защищенного соединения (с таймаутом 10 секунд).
2. **Session Identification**: Клиент отправляет 16 байт (Raw UUID) непосредственно в поток DTLS.
3. **Tunnel Traffic**: После отправки UUID начинается двусторонний обмен пакетами WireGuard.

Это позволяет прокси-серверу идентифицировать сессию пользователя и поддерживать стабильный `Endpoint` на стороне WireGuard сервера, вне зависимости от количества активных DTLS-потоков или смены IP-адресов клиента.

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

---

## 7. Хранение настроек

### TurnSettingsStore

Настройки TURN сохраняются в отдельном JSON-файле `<tunnel>.turn.json` рядом с конфигом WireGuard. Это позволяет:
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

---

## 8. Архитектура запуска TURN

```
GoBackend.setStateInternal()
  → builder.establish()                    ← Туннель создан
  → wgTurnOn()                             ← Go backend запущен
  → service.protect() для сокетов WireGuard
  → TurnProxyManager.onTunnelEstablished() ← TURN запускается ПОСЛЕ туннеля
    → TurnBackend.waitForVpnServiceRegistered() ← Ждём JNI
    → wgTurnProxyStart()                   ← Запуск TURN прокси
      → VK Auth для получения credentials
      → Подключение к TURN серверу (4 потока)
      → DTLS handshake для каждого потока
      → wgProtectSocket() для всех сокетов
```

**Преимущества:**
- TURN запускается после создания туннеля, что гарантирует работу `VpnService.protect()` для всех сокетов
- Явная синхронизация через CountDownLatch исключает гонки условий
- Сокеты WireGuard защищаются до запуска TURN
