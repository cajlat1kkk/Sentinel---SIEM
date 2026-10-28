# Архитектура Sentinel SIEM

```text
Qt Widgets desktop (C++20, без web runtime)
  ├─ Store / QPSQL ───────── PostgreSQL
  ├─ Collector / QUdpSocket ─ syslog 127.0.0.1 + импорт JSONL/EVE
  ├─ Scanner / QtConcurrent ─ потоковое SHA-256/EICAR + clamscan
  ├─ Engines / QProcess ───── siem-dpdk (EAL + ethdev RX/TX)
  │                       └─ vppctl → локальный VPP CLI socket
  └─ Firewall adapter ─────── policy JSON → elevated helper
                                         ├─ nftables, Linux
                                         └─ Windows Firewall COM
```

## Данные и жизненный цикл

Основная БД — PostgreSQL через Qt QPSQL/libpq. SQLite существует только как изолированное хранилище демо и быстрых тестов. Приложение не переключается на неё при ошибке PostgreSQL.

`Store` создаёт схему и стандартные правила при первом подключении. Все входящие данные передаются через prepared statements. Событие, обновление актива, отметки корреляции и инцидент записываются одной транзакцией. Время нормализовано в UTC ISO8601; отображение использует часовую зону desktop. Корреляция использует время получения, чтобы исторический импорт не подменял часы окна. Метки совпадений хранятся до суток, что соответствует максимальному окну правила.

Таблицы: `events`, `incidents`, `assets`, `rules`, `matches`, `firewall`, `quarantine`, `audit`, `meta`. Поля `raw` и время хранятся как TEXT для общей схемы PostgreSQL/demo. ID рабочих таблиц — BIGSERIAL в PostgreSQL. JSON-экспорт не заменяет полную резервную копию PostgreSQL.

Collector и БД принадлежат UI-потоку. UDP обрабатывается порциями по 100 сообщений с возвратом в event loop. UI обновления объединяются таймером. Это MVP архитектура для умеренной нагрузки; DPDK throughput не равен throughput транзакций SIEM. DPDK экспортирует максимум 500 событий в секунду, агрегаты учитывают все пакеты.

Scanner работает в QtConcurrent, не обращается к SQL из worker-потока. Результаты передаются обратно в UI. Отмена кооперативная; ClamAV имеет отдельный процесс и тайм-аут. Отдельные процессы также изолируют сбой EAL/VPP от GUI.

## Граница привилегий

Главный GUI не запускается от root. Firewall helper получает только JSON с ограничением размера и повторно валидирует адреса, протоколы, порты и действия. На Linux использует фиксированный путь `/usr/sbin/nft` или `/usr/bin/nft`; JSON не превращается в shell-команду. nft получает сгенерированный конфиг через stdin. Имена/тексты правил не интерполируются в nft-синтаксис.

Изменяется только собственная таблица `inet sentinel_siem`. Проверка и применение отдельны, применение транзакционно. Сохранённая в БД предыдущая политика позволяет ручной откат; это не watchdog с автоматическим возвратом при потере связи.

На Windows helper повышается через ShellExecuteEx `runas` и использует COM. Перечень операций ограничен управлением правилами SentinelSIEM; замена не атомарна. Windows driver dataplane, WFP callout, DPI TLS и VPP ACL не реализованы.

Антивирус не удаляет обнаруженное автоматически. Перед ручным перемещением сравнивается SHA-256, копия создаётся через QSaveFile и повторно проверяется. В среде с враждебным локальным процессом, меняющим путь между проверкой и удалением, обычные path-based операции не заменяют системную EDR-службу и файловый minifilter.

## Пакетный сенсор

`siem-dpdk` реально связывается с libdpdk, поднимает EAL, mempool, очереди ethdev и вызывает `rte_eth_rx_burst`. В inline вызывает `rte_eth_tx_burst` в парный порт. Мониторинг освобождает mbuf после анализа. Метаданные и счётчики идут JSONL через stdout, диагностика EAL — stderr.

Разбираются Ethernet, до двух VLAN tags, IPv4/IPv6 без extensions, TCP/UDP. HTTP-сигнатуры проверяются в первых 8 КБ payload одного пакета после percent-decoding. Нет TCP/IP reassembly, conntrack, TLS MITM, flow classification, fail-open hardware bypass. Метки в UI отражают только успешно запущенный процесс/полученный ответ.

VPP adapter выполняет только `vppctl -s SOCKET show interface`, с тайм-аутом 5 секунд. Состояние показывается как снимок по запросу, производные вымышленные rates отсутствуют.

## Официальные справочники

- [DPDK: запуск приложений и подготовка системы](https://doc.dpdk.org/guides/linux_gsg/build_sample_apps.html)
- [DPDK PCAP PMD](https://doc.dpdk.org/guides/nics/pcap.html)
- [FD.io VPP CLI](https://fd.io/docs/vpp/v2101/reference/cmdreference/index.html)
- [ClamAV: Scanning](https://docs.clamav.net/manual/Usage/Scanning.html)
- [nftables reference](https://www.netfilter.org/projects/nftables/manpage.html)
- [Windows INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)
