# WireGuard Android с VK TURN Proxy

[English version (README.en.md)](README.en.md)

Это специализированный форк официального клиента [WireGuard Android](https://git.zx2c4.com/wireguard-android) с интегрированной поддержкой **VK TURN Proxy**.

Проект позволяет инкапсулировать трафик WireGuard в потоки DTLS/TURN, используя инфраструктуру VK Calls. Это обеспечивает надежный способ обхода сетевых ограничений при сохранении высокой производительности и стабильности.

## Ключевые особенности

- **Нативная интеграция**: TURN-клиент встроен напрямую в `libwg-go.so` для максимальной производительности и минимального расхода заряда батареи.
- **Авторизация VK**: Автоматическое получение учетных данных TURN через анонимные токены VK Calls.
- **Sticky Stream Failover**: Высокая надежность за счет нескольких параллельных потоков DTLS с «липкой» маршрутизацией для обеспечения стабильности сессии WireGuard.
- **Умный DNS**: Встроенный обход системного DNS для работы в ограниченных сетях, гарантирующий подключение к TURN даже при подмене DNS-запросов.
- **Удобная настройка**: Параметры TURN хранятся прямо в стандартных `.conf` файлах WireGuard в виде специальных комментариев-метаданных (`#@wgt:`).
- **Защита VpnService**: Весь трафик прокси автоматически защищен от попадания в VPN-петлю.

## Благодарности

Этот проект построен на базе:
1. **[Official WireGuard Android](https://git.zx2c4.com/wireguard-android)** — основное приложение VPN и пользовательский интерфейс.
2. **[vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy)** — оригинальная концепция и реализация прокси на языке Go.

## Сборка

```bash
$ git clone --recurse-submodules https://github.com/your-repo/wireguard-turn-android
$ cd wireguard-turn-android
$ ./gradlew assembleRelease
```

## Настройка

Вы можете включить прокси в редакторе туннеля. Настройки будут добавлены в секцию Peer вашей конфигурации:

```ini
[Peer]
PublicKey = <key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0

# [Peer] TURN extensions
#@wgt:EnableTURN = true
#@wgt:IPPort = 1.2.3.4:56000
#@wgt:VKLink = https://vk.com/call/join/...
#@wgt:StreamNum = 4
```

Для получения подробной технической информации см. [info/TURN_INTEGRATION_DETAILS.md](info/TURN_INTEGRATION_DETAILS.md).

## Участие в проекте

Для перевода интерфейса используйте оригинальный [WireGuard Crowdin](https://crowdin.com/project/WireGuard). При обнаружении технических ошибок, связанных с интеграцией TURN, пожалуйста, создавайте Issue в этом репозитории.
