# Sentinel SIEM

**Единая консоль событий безопасности и управления компьютерами локальной сети.**

Sentinel собирает события с Linux и Windows, показывает состояние компьютеров,
помогает расследовать инциденты и запускать антивирусные проверки. Главный
компьютер хранит данные в PostgreSQL; на остальных работает фоновый агент.
Интерфейс — русский и английский. Версия: **0.3.0**.

## Возможности

- Централизованные события, поиск, корреляция, инциденты и экспорт.
- Инвентаризация ПК, группы, политики и удалённые задания проверки.
- Антивирусные проверки и карантин; подключение ClamAV для сигнатурного анализа.
- Шифрованные соединения с взаимной проверкой сертификатов — mTLS.
- Мастер выбора роли, выпуск сертификатов, диагностика и копирование PostgreSQL.
- **Сетевой радар VPP + DPDK:** IP-потоки, ведущие источники трафика, признаки
  сканирования и высокого объёма. Нужен выделенный сенсорный порт и SPAN/TAP.
- Метрики Prometheus и готовые панели Grafana для сервера и радара.

## Содержание

1. [Установка и запуск](#1-установка-и-запуск)
2. [Схема локальной сети](#2-схема-локальной-сети)
3. [Главный компьютер](#3-главный-компьютер)
4. [Подключение дополнительных ПК](#4-подключение-дополнительных-пк)
5. [Консоль аналитика](#5-консоль-аналитика)
6. [Сетевой радар](#6-сетевой-радар)
7. [Мониторинг и обслуживание](#7-мониторинг-и-обслуживание)
8. [Сборка приложения](#8-сборка-приложения)
9. [Решение проблем](#9-решение-проблем)

## 1. Установка и запуск

Установите пакет Sentinel на каждый участвующий компьютер. Если готового пакета
нет, соберите его по [разделу 8](#8-сборка-приложения). Пакеты не входят в Git;
файлы `dist/` появляются после сборки. Linux-пакет должен соответствовать
дистрибутиву и версиям его библиотек.

**CachyOS / Arch Linux**, из каталога с пакетом:

```bash
sudo pacman -S --needed polkit
sudo pacman -U ./sentinel-siem-0.3.0-1-x86_64.pkg.tar.zst
sentinel-siem
```

**Ubuntu / Debian**, из каталога с совместимым DEB:

```bash
sudo apt install ./sentinel-siem-0.3.0-Linux.deb
sentinel-siem
```

**Windows 10/11 x64:** запустите машинный EXE-установщик и установите приложение
в `C:\Program Files\Sentinel SIEM`. Откройте Sentinel из меню «Пуск» или PowerShell:

```powershell
& 'C:\Program Files\Sentinel SIEM\bin\sentinel-siem.exe'
```

При первом запуске мастер предлагает роли:

| Роль | Где выбрать | Что работает |
|---|---|---|
| Главный сервер и консоль | Главный ПК | Сервер, общая БД и консоль администратора |
| Управляемый компьютер | Каждый наблюдаемый ПК | Фоновый агент |
| Консоль оператора | Рабочее место аналитика | Подключение к общим данным через сервер |
| Локальная консоль PostgreSQL | Отдельное рабочее место | Прямое подключение к БД |

Полезные команды установленного приложения:

```bash
sentinel-siem --setup                         # Повторно выбрать роль и подключение.
sentinel-siem --fleet-connect                 # Выбрать профиль консоли парка.
sentinel-siem --demo --no-engines              # Посмотреть интерфейс без БД и сенсоров.
sentinel-siem --demo --no-engines --language en_US
sentinel-siem --help
```

GUI запускайте от обычного пользователя. Установка службы отдельно требует прав
администратора. Демоданные временные и удаляются при выходе. Язык переключается
кнопкой **Язык** в консоли парка или в **Настройках** локальной консоли; затем
перезапустите приложение.

## 2. Схема локальной сети

```text
pc-01: агент ──────┐
pc-02: агент ──────┼── TCP 7443 / mTLS ── Главный компьютер
pc-03: агент ──────┘                     ├─ siem-server
                                        ├─ PostgreSQL
Консоль аналитика ── TCP 7443 / mTLS ─────└─ консоль администратора
```

В инструкции используется пример:

| Параметр | Значение |
|---|---|
| Подсеть | `192.168.1.0/24` |
| Главный компьютер | `192.168.1.10`, Linux |
| Клиенты | `pc-01`, `pc-02`, …; Linux или Windows |
| Sentinel RPC | TCP `7443` |
| PostgreSQL на главном ПК | `127.0.0.1:5432`, база и пользователь `sentinel` |
| Метрики / локальный IPFIX | `127.0.0.1:9108` / UDP `127.0.0.1:4740` |

Подключите ПК к одному роутеру/коммутатору или обычной Wi-Fi-сети без изоляции
клиентов. В DHCP роутера закрепите свободный адрес главного ПК. **Замените
`192.168.1.10` и подсеть на свои значения.** Клиентам можно оставить DHCP.
Sentinel использует готовую LAN: не создаёт DHCP, роутер, Wi-Fi или VPN.

Проверьте адреса: `ip -br address` на Linux, `ipconfig` на Windows. После запуска
сервера проверьте порт с Windows-клиента:

```powershell
Test-NetConnection 192.168.1.10 -Port 7443
```

Разрешите входящий TCP 7443 на главном ПК из своей подсети в используемом firewall.
Если уже используется UFW, для данного примера:

```bash
sudo ufw allow from 192.168.1.0/24 to 192.168.1.10 port 7443 proto tcp comment 'Sentinel fleet'
```

PostgreSQL, IPFIX и Prometheus клиентам открывать не нужно. Проброс портов из
интернета не требуется. VPP/DPDK не нужны для обычного подключения агентов.

## 3. Главный компьютер

Ниже — последовательная установка на **новый Linux-сервер** после установки
пакета Sentinel. Команды выполняются обычным пользователем; `sudo` указан там,
где нужны права администратора. Не создавайте повторно существующие БД и ключи.

### 3.1. Подготовьте PostgreSQL

На **CachyOS / Arch**, если PostgreSQL ещё не настроен:

```bash
sudo pacman -S --needed postgresql

# Только для нового пустого каталога данных!
sudo -u postgres initdb -D /var/lib/postgres/data \
  --locale=C.UTF-8 --encoding=UTF8 --auth-local=peer --auth-host=scram-sha-256
sudo systemctl enable --now postgresql.service
```

На **Ubuntu / Debian** пакет обычно создаёт кластер при установке; вручную
`initdb` не выполняйте:

```bash
sudo apt update
sudo apt install postgresql postgresql-client
sudo systemctl enable --now postgresql.service
```

Общие команды — создать роль и базу. В запросе `createuser` задайте пароль БД;
**тот же пароль** понадобится при создании профиля.

```bash
sudo -u postgres createuser --pwprompt --no-superuser --no-createdb --no-createrole sentinel
sudo -u postgres createdb --owner=sentinel sentinel
psql -h 127.0.0.1 -p 5432 -U sentinel -d sentinel -W -c 'SELECT 1;'
```

Ожидаемый результат последней команды — значение `1`. PostgreSQL оставьте
доступным локально. Для существующей БД используйте её параметры и проверьте
пароль/`pg_hba.conf`, вместо повторного создания роли и базы.

### 3.2. Создайте сертификаты и профили

Команды выполняйте в одном терминале. `SENTINEL_DIR` — постоянный каталог
администратора. В новом терминале повторите строки `export`.

```bash
export SENTINEL_DIR="$HOME/.local/share/sentinel"
export SENTINEL_SERVER_IP=192.168.1.10
export SENTINEL_TOOLS=/usr/share/doc/sentinel-siem/scripts
umask 077
mkdir -p "$SENTINEL_DIR"
chmod 700 "$SENTINEL_DIR"

python3 "$SENTINEL_TOOLS/sentinel-maintenance.py" issue-deployment \
  --server-name "$SENTINEL_SERVER_IP" --output "$SENTINEL_DIR/pki"
```

Создаются отдельные личности `pki/server`, `pki/operator` и CA в `pki/ca`.
Каталог `pki` должен быть новым. Используйте один CA для всего парка. Клиенты
должны подключаться по IP/DNS, указанному в `--server-name`.

Следующая команда запросит **пароль PostgreSQL из шага 3.1** и создаст
`main/server.json`, `main/console.json`. Пароль не отображается:

```bash
python3 - <<'PY'
import getpass, json, os
from pathlib import Path
os.umask(0o077)
root = Path(os.environ['SENTINEL_DIR']).resolve()
profile = root / 'main'
profile.mkdir(mode=0o700)  # Существующие профили не перезаписываются.
password = getpass.getpass('Пароль PostgreSQL для роли sentinel: ')
if not password:
    raise SystemExit('Пустой пароль не допускается')
with (profile / 'postgres-password').open('x') as file:
    file.write(password + '\n')
def identity(name):
    base = root / 'pki' / name
    return dict(ca=str(base / 'ca.crt'), certificate=str(base / 'identity.crt'),
                private_key=str(base / 'identity.key'))
server = dict(identity('server'), listen='0.0.0.0', port=7443, retention_days=90,
              database=dict(host='127.0.0.1', port=5432, name='sentinel', user='sentinel',
                            password_file=str(profile / 'postgres-password')),
              metrics=dict(enabled=True, listen='127.0.0.1', port=9108),
              radar=dict(enabled=False, listen='127.0.0.1', port=4740, exporter='127.0.0.1'))
console = dict(identity('operator'), host=os.environ['SENTINEL_SERVER_IP'], port=7443)
for name, value in [('server.json', server), ('console.json', console)]:
    with (profile / name).open('x') as file:
        json.dump(value, file, indent=2)
print('Профили:', profile)
PY
```

Вместо генерации JSON можно открыть `sentinel-siem --setup`, выбрать **Главный
сервер и консоль**, ввести параметры из таблицы раздела 2 и выбрать файл пароля
и сертификаты. Если PKI уже создан, укажите существующие файлы. Кнопка
автоматического выпуска предназначена для нового комплекта.

### 3.3. Установите службу и откройте консоль

```bash
sudo python3 "$SENTINEL_TOOLS/install-fleet-service.py" server \
  "$SENTINEL_DIR/main/server.json" \
  --operator-certificate "$SENTINEL_DIR/pki/operator/identity.crt" \
  --operator-name Administrator --operator-role admin

systemctl status sentinel-server.service --no-pager
sentinel-siem --fleet "$SENTINEL_DIR/main/console.json"
```

Установщик копирует служебные ключи и пароль в `/etc/sentinel-server`, проверяет
конфигурацию, регистрирует администратора и включает автозапуск. Сервер работает
от пользователя `sentinel-server`. GUI можно закрывать — служба продолжает работу.
Профиль консоли и ключ оператора должны оставаться доступны вашему пользователю.

Проверьте вход администратора:

```bash
siem-fleetctl --config "$SENTINEL_DIR/main/console.json" session
```

Ожидается JSON с `"role": "admin"`. Если команда не проходит, исправьте
подключение до регистрации клиентских ПК.

## 4. Подключение дополнительных ПК

Каждому компьютеру нужны **свой сертификат и свой код подключения**.
Не копируйте одну личность на несколько устройств.

### 4.1. На главном компьютере: подготовьте pc-01

```bash
export SENTINEL_DIR="$HOME/.local/share/sentinel"
export SENTINEL_TOOLS=/usr/share/doc/sentinel-siem/scripts
export SENTINEL_NODE=pc-01
umask 077

python3 "$SENTINEL_TOOLS/sentinel-maintenance.py" issue-identity \
  --ca-dir "$SENTINEL_DIR/pki/ca" --name "$SENTINEL_NODE" \
  --output "$SENTINEL_DIR/enrollment/$SENTINEL_NODE"

python3 - <<'PY'
import json, os, subprocess
from pathlib import Path
os.umask(0o077)
node = Path(os.environ['SENTINEL_DIR']) / 'enrollment' / os.environ['SENTINEL_NODE']
fingerprint = subprocess.check_output(['siem-fleetctl', '--fingerprint',
    str(node / 'identity/identity.crt')], text=True).strip()
with (node / 'request.json').open('x') as file:
    json.dump(dict(identity=fingerprint, group='default'), file)
PY

siem-fleetctl --config "$SENTINEL_DIR/main/console.json" \
  --params "$SENTINEL_DIR/enrollment/$SENTINEL_NODE/request.json" \
  --output "$SENTINEL_DIR/enrollment/$SENTINEL_NODE/response.json" enrollment.create

python3 - <<'PY'
import json, os
from pathlib import Path
os.umask(0o077)
node = Path(os.environ['SENTINEL_DIR']) / 'enrollment' / os.environ['SENTINEL_NODE']
token = json.loads((node / 'response.json').read_text())['token']
with (node / 'identity/enrollment.token').open('x') as file:
    file.write(token + '\n')
PY

tar -czf "$SENTINEL_DIR/enrollment/$SENTINEL_NODE.tar.gz" \
  -C "$SENTINEL_DIR/enrollment/$SENTINEL_NODE/identity" .
```

Код действует **один час**. За это время перенесите `pc-01.tar.gz` на нужный ПК
в Downloads/«Загрузки» и запустите агент. Используйте защищённую передачу или
доверенный носитель: архив содержит закрытый ключ. Передаются только `ca.crt`,
`identity.crt`, `identity.key`, `enrollment.token`. Ключи CA/администратора и пароль
PostgreSQL клиенту не нужны.

Вариант через GUI: **Компьютеры → Подключить компьютер**, выбрать публичный
`identity.crt`, группу `default` и сохранить `enrollment.token` рядом с личностью
ПК. Если код истёк, выдайте новый для того же сертификата; новый CA не нужен.

### 4.2. На Linux-клиенте: установите агент

Установите пакет Sentinel. Команды предполагают, что архив лежит в
`$HOME/Downloads/pc-01.tar.gz`; при другом имени папки исправьте путь.

```bash
export SENTINEL_NODE=pc-01
export SENTINEL_SERVER_IP=192.168.1.10
export SENTINEL_CLIENT_DIR="$HOME/.local/share/sentinel/$SENTINEL_NODE"
umask 077
mkdir -p "$HOME/.local/share/sentinel"
mkdir "$SENTINEL_CLIENT_DIR"
tar -xzf "$HOME/Downloads/$SENTINEL_NODE.tar.gz" -C "$SENTINEL_CLIENT_DIR"

python3 - <<'PY'
import json, os
from pathlib import Path
os.umask(0o077)
root = Path(os.environ['SENTINEL_CLIENT_DIR']).resolve()
config = dict(server=dict(host=os.environ['SENTINEL_SERVER_IP'], port=7443,
    ca=str(root / 'ca.crt'), certificate=str(root / 'identity.crt'), private_key=str(root / 'identity.key')),
    state_dir='/var/lib/sentinel-agent', enrollment_token_file=str(root / 'enrollment.token'),
    manage_firewall=False, collect_system=True, syslog_port=5514,
    queue_max_events=100000, queue_max_mib=256, scan_roots=['/home'])
with (root / 'agent.json').open('x') as file:
    json.dump(config, file, indent=2)
PY

sudo python3 /usr/share/doc/sentinel-siem/scripts/install-fleet-service.py \
  agent "$SENTINEL_CLIENT_DIR/agent.json"

systemctl status sentinel-agent.service --no-pager
logger --udp --server 127.0.0.1 --port 5514 'Sentinel LAN test pc-01'
```

Агент работает при закрытом GUI. Управление firewall изначально выключено;
разрешённые каталоги сканирования задаёт `scan_roots`.

### 4.3. На Windows-клиенте: установите агент

Установите машинный EXE-пакет. В обычном PowerShell распакуйте архив:

```powershell
$Node = 'pc-01'
$ClientDir = Join-Path $env:LOCALAPPDATA "Sentinel\$Node"
if (Test-Path $ClientDir) { throw 'Используйте существующие файлы или новый каталог' }
New-Item -ItemType Directory -Path $ClientDir -Force | Out-Null
$UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls.exe $ClientDir /inheritance:r /grant:r "*${UserSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw 'Не удалось ограничить права каталога' }
tar.exe -xzf "$env:USERPROFILE\Downloads\$Node.tar.gz" -C $ClientDir
if ($LASTEXITCODE -ne 0) { throw 'Не удалось распаковать архив' }
Write-Output $ClientDir
& 'C:\Program Files\Sentinel SIEM\bin\sentinel-siem.exe' --setup
```

В мастере выберите **Управляемый компьютер**:

| Поле | Что ввести |
|---|---|
| DNS/IP сервера | `192.168.1.10` |
| Порт | `7443` |
| CA-сертификат | `ca.crt` из напечатанного `$ClientDir` |
| Сертификат | `identity.crt` из того же каталога |
| Закрытый ключ | `identity.key` из того же каталога |
| Одноразовый код | `enrollment.token` из того же каталога |
| Каталоги сканирования | Например, `C:\Users` |
| Управление firewall | Выключено для первого подключения |
| Каталог профиля | Новый подкаталог `profile` внутри `$ClientDir` |

Завершите мастер и подтвердите UAC для установки службы. Портативная установка
в пользовательский каталог не подходит для службы. Проверьте работу:

```powershell
Get-Service SentinelAgent
Test-NetConnection 192.168.1.10 -Port 7443
$Udp = [Net.Sockets.UdpClient]::new()
$Message = [Text.Encoding]::UTF8.GetBytes('Sentinel LAN test pc-01 Windows')
[void]$Udp.Send($Message, $Message.Length, '127.0.0.1', 5514)
$Udp.Dispose()
```

### 4.4. Проверьте доставку и подключите остальные ПК

На главном ПК откройте **Компьютеры**: клиент должен появиться, время последней
связи — обновляться. В **Событиях** найдите `Sentinel LAN test pc-01`.
В таблице отображается имя ОС компьютера; имя сертификата `pc-01` не переименовывает ПК.
Повторите проверку через несколько минут и после перезагрузки клиента.
Один статус `active` или открытый порт не подтверждает доставку по mTLS.

Для **pc-02** повторите шаги 4.1–4.4 с `SENTINEL_NODE=pc-02` / `$Node='pc-02'`.
Сервер, БД и CA повторно не создаются. Для сбора журналов главного ПК установите
на него отдельный агент со своей личностью — сервер сам их не читает.

## 5. Консоль аналитика

Агент и оператор — разные роли. Аналитик подключается к серверу без пароля БД
и без сертификата администратора. На главном ПК:

```bash
export SENTINEL_DIR="$HOME/.local/share/sentinel"
python3 /usr/share/doc/sentinel-siem/scripts/sentinel-maintenance.py issue-identity \
  --ca-dir "$SENTINEL_DIR/pki/ca" --name analyst-01 --output "$SENTINEL_DIR/analyst-01"

siem-server --config "$SENTINEL_DIR/main/server.json" \
  --add-operator "$SENTINEL_DIR/analyst-01/identity/identity.crt" \
  --name Analyst --role analyst
```

`--add-operator` регистрирует личность и завершается, не запускает второй сервер.
Передайте аналитику только три файла из `analyst-01/identity`. На его ПК установите
Sentinel, запустите `--setup`, выберите **Консоль оператора**, укажите
`192.168.1.10:7443` и локальные пути к файлам. `analyst` просматривает данные
и меняет статусы инцидентов; управление парком требует `admin`.

## 6. Сетевой радар

Вкладки **Сетевой радар** и **Источники трафика** показывают IP/порты/протокол,
пакеты, байты и ведущие источники за пять минут. Признаки сканирования отображаются
в событиях и инцидентах. Колонка ПК сопоставляет IP со свежим отчётом агента;
это подсказка для расследования, не доказательство источника пакета.

Для наблюдения LAN подключите выделенный Ethernet-порт к SPAN/TAP. На подготовленном
стенде VPP 25.10 + DPDK 25.07 с RTL8168 `0000:04:00.0`, **из каталога исходников**:

```bash
bash scripts/build-vpp-radar.sh
sudo python3 scripts/install-vpp-radar.py \
  .dev/vpp-dpdk-25.07-build/lib/vpp_plugins/flowprobe_plugin.so
```

Установщик создаёт backup/rollback, перезапускает существующий `vpp.service`
и проверяет устойчивость. Адреса, маршруты, Wi-Fi и VPN не настраиваются.
Для нового компьютера сначала подготовьте совместимые VPP, DPDK и NIC:
это не универсальный установщик VPP.

Включите `radar.enabled=true` флажком при настройке главного ПК либо в установленном
`/etc/sentinel-server/server.json` после резервного копирования; перезапустите
`sentinel-server.service`. **«Приёмник слушает» не означает «видит сеть»**:
проверьте поступление свежих потоков. Подробности и откат:
[NETWORK_RADAR.md](docs/NETWORK_RADAR.md).

## 7. Мониторинг и обслуживание

### Prometheus и Grafana

На главном ПК:

```bash
curl --fail http://127.0.0.1:9108/metrics
```

В комплект входят панели сервера и **Sentinel · Network radar**.
Prometheus/Grafana устанавливаются отдельно; provisioning находится в
`/usr/share/doc/sentinel-siem/observability`. Настройка сервисов:
[инструкция мониторинга](packaging/observability/README.md).
Доступ другим ПК к Grafana включайте с аутентификацией. IPFIX-графики отражают
поступившие наблюдения, а не точные аппаратные счётчики NIC.

### Диагностика и резервные копии

В приложении: **Обслуживание**. Те же действия на главном ПК из терминала:

```bash
export SENTINEL_DIR="$HOME/.local/share/sentinel"
export SENTINEL_TOOLS=/usr/share/doc/sentinel-siem/scripts

python3 "$SENTINEL_TOOLS/sentinel-maintenance.py" diagnose \
  --config "$SENTINEL_DIR/main/console.json"
python3 "$SENTINEL_TOOLS/sentinel-maintenance.py" diagnose \
  --config "$SENTINEL_DIR/main/server.json" --service sentinel-server.service
python3 "$SENTINEL_TOOLS/sentinel-maintenance.py" backup \
  --config "$SENTINEL_DIR/main/server.json" --output "$SENTINEL_DIR/backups"
```

Последняя команда печатает `backup_directory`. Подставьте его в проверку:

```bash
python3 "$SENTINEL_TOOLS/sentinel-maintenance.py" verify-backup \
  --output /полный/путь/из/backup_directory
```

Копия включает таблицы Fleet и радара. Ключи, конфигурации, роли PostgreSQL,
карантин и очереди агентов сохраняйте отдельно. SHA-256/чтение архива не заменяют
пробное восстановление в отдельную БД: [MAINTENANCE.md](docs/MAINTENANCE.md).
Нужны Python 3.11+, OpenSSL и PostgreSQL client tools в PATH; на Windows они
устанавливаются отдельно. Автопродление сертификатов, расписание/ротация копий
и автоматическое обновление парка пока не реализованы.

### После перезагрузки

Установщики включают автозапуск служб. На Linux:

```bash
# На главном ПК:
systemctl is-enabled sentinel-server.service
systemctl status sentinel-server.service --no-pager

# На управляемом ПК:
systemctl is-enabled sentinel-agent.service
systemctl status sentinel-agent.service --no-pager
```

На Windows: `Get-Service SentinelAgent`. Консоль открывайте через
`sentinel-siem --fleet-connect`; фоновым службам GUI не нужен.
Перед обновлением пакета закройте GUI, сделайте копию БД/конфигурации и остановите
службу Sentinel на обновляемом ПК; после установки запустите её и проверьте доставку.

## 8. Сборка приложения

Команды выполняются из корня исходников. Нужны C++20, CMake 3.24+, Qt 6.4+,
OpenSSL и Python 3.11+. Для английского каталога нужен Qt Linguist/lrelease.

### Linux: сборка и запуск из исходников

Зависимости CachyOS / Arch:

```bash
sudo pacman -S --needed base-devel cmake ninja pkgconf qt6-base qt6-svg \
  qt6-tools postgresql-libs openssl python
```

Зависимости Ubuntu 24.04 / Debian 12+:

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build pkg-config qt6-base-dev \
  qt6-svg-dev qt6-l10n-tools libqt6sql6-psql libqt6sql6-sqlite libpq-dev \
  libssl-dev openssl python3
```

Общие команды:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DSIEM_WITH_DPDK=OFF
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
./build/sentinel-siem --demo --no-engines
./build/sentinel-siem --setup
```

Приёмник радара собирается и с `SIEM_WITH_DPDK=OFF`: DPDK работает внутри отдельно
установленного VPP. Опция `ON` нужна для самостоятельного `siem-dpdk`; для неё
установите DPDK development files. Сборка в `build/` сама не устанавливает службы:
для них нужен системный пакет. Если каталог сборки другой, замените `build` в командах.

Локальная БД разработки: `bash scripts/run-local.sh --no-engines`;
остановка только этой БД: `bash scripts/stop-local-db.sh`.

### Arch / CachyOS: установочный пакет

```bash
sudo pacman -S --needed dpdk polkit
bash scripts/package-arch.sh
sudo pacman -U dist/arch/sentinel-siem-0.3.0-1-x86_64.pkg.tar.zst
```

Скрипт собирает текущие исходники, включая самостоятельный DPDK-сенсор.
`makepkg` запускается без sudo. Для другого ПК скопируйте `.pkg.tar.zst`, затем
установите командой из раздела 1.

### Ubuntu / Debian: DEB

При установленном Docker с доступом текущего пользователя:

```bash
bash scripts/package-deb.sh
sudo apt install ./dist/deb/sentinel-siem-0.3.0-Linux.deb
```

По умолчанию используется Ubuntu 24.04. Сборка для Debian 13:
`SIEM_DEB_BASE=debian:13-slim bash scripts/package-deb.sh`.
Пакет для одного дистрибутива не устанавливайте на несовместимый другой.

### Windows: EXE

В Developer PowerShell Visual Studio 2022, с Qt 6.8 MSVC, Linguist Tools, CMake,
Ninja и NSIS в PATH. Укажите фактический каталог PostgreSQL client DLL:

```powershell
$env:SIEM_PG_RUNTIME_DIR = 'C:\Program Files\PostgreSQL\17\bin'
.\packaging\windows\build.ps1
```

EXE появится в `build-windows/`. Для служб используйте машинную MSVC/CPack-сборку;
portable/per-user сборка предназначена для консоли.

### Проверка интеграции

При установленных PostgreSQL server/client tools и OpenSSL:

```bash
python3 scripts/test-fleet.py --build build
```

Тест поднимает временный стенд и проверяет mTLS, роли, доставку, восстановление
очереди, задания, IPFIX-радар, метрики и восстановление копии БД. Это не проверка
вашей физической LAN. Результаты и границы проверок — [VALIDATION.md](docs/VALIDATION.md).

## 9. Решение проблем

| Симптом | Что проверить |
|---|---|
| Клиент не подключается | IP сервера, TCP 7443, firewall, изоляцию клиентов на роутере |
| TLS verification failed | Часы ПК, срок сертификата, CA, совпадение IP/DNS с SAN |
| Enrollment denied | Код действует час и привязан к конкретному сертификату |
| Operator access denied | Регистрацию оператора; не используется ли сертификат агента |
| Сервер не запускается | БД, пароль, права файлов, занятость портов и журнал службы |
| ПК виден, событий нет | Сбор журналов, очередь, syslog 5514 и тестовую запись |
| Радар пуст | `radar.enabled`, локальный экспортёр, link/carrier и SPAN/TAP |
| Нет английского перевода | QM-каталог, сборку с lrelease и перезапуск GUI |
| Каталог уже существует | Генераторы защищают ключи/профили; используйте их либо новый каталог |

Журналы Linux:

```bash
journalctl -u sentinel-server.service -n 100 --no-pager
journalctl -u sentinel-agent.service -n 100 --no-pager
```

Sentinel не заменяет полноценный EDR/IPS. Сигнатурный антивирус требует ClamAV
с актуальными базами; сетевые эвристики требуют проверки аналитиком.
Автоматическое блокирование по сигналам радара не выполняется.

## Документация

- [Установка и роли](docs/SETUP.md), [управляемый парк](docs/FLEET.md).
- [Сертификаты, диагностика и копии БД](docs/MAINTENANCE.md).
- [Сетевой радар](docs/NETWORK_RADAR.md), [VPP/DPDK/RTL8168](docs/VPP_DPDK_R8169.md).
- [Prometheus/Grafana](packaging/observability/README.md), [языки](docs/LOCALIZATION.md).
- [NGFW](docs/NGFW.md), [сетевой стенд](docs/NETWORK_LAB.md).
- [Архитектура](docs/ARCHITECTURE.md), [карта проекта](docs/PROJECT_MAP.md), [проверки](docs/VALIDATION.md).
