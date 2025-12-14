# SOV — учебная система обнаружения вторжений (Node + Network IDS)

SOV — учебный проект СОВ: сенсоры (узловой + сетевой) отправляют события на центральный анализатор.
Анализатор сопоставляет события с правилами (rules.yaml), пишет аудит и (при совпадении) создаёт алерты.
Управление и мониторинг — через CLI по тому же сетевому протоколу.

## 1) Компоненты и роли

### Компоненты (бинарники)

- **sov-analyzer** — центральный анализатор/сервер.
- **sov-sensor-node** — узловой сенсор (Linux логи / Windows Event Log).
- **sov-sensor-net** — сетевой сенсор (pcap/Npcap).
- **sov-admin-cli** — управление (push ruleset, status).
- **sov-operator-cli** — мониторинг (status, подписка на алерты).

### Роли (RBAC)

Роли берутся **из сертификата клиента** (OU в subject):

- `OU=Sensor` — сенсоры
- `OU=SecurityAdmin` — админ CLI
- `OU=Operator` — оператор CLI

> Примечание: `roles.yaml` может остаться “локальной справкой”, но доступ в системе задаётся mTLS-сертификатами.

## 2) Структура проекта

```text
sov/
├─ Cargo.toml            # workspace
├─ sov-core/             # типы, события, правила, конфиги
├─ sov-transport/        # протокол + TLS(mTLS) утилиты
├─ sov-analyzer/         # анализатор (TCP/TLS listener)
├─ sov-sensor-node/      # узловой сенсор
├─ sov-sensor-net/       # сетевой сенсор (pcap)
├─ sov-admin-cli/        # CLI администратора (сетевой)
├─ sov-operator-cli/     # CLI оператора (сетевой)
├─ config/               # YAML-конфиги + pki
│  ├─ analyzer.yaml
│  ├─ rules.yaml
│  ├─ node-sensor.yaml
│  ├─ net-sensor.yaml
│  ├─ admin-cli.yaml
│  ├─ operator-cli.yaml
│  └─ pki/
│     ├─ ca.crt
│     ├─ analyzer.crt / analyzer.key
│     ├─ admin.crt   / admin.key
│     ├─ operator.crt/ operator.key
│     ├─ sensor-node.crt / sensor-node.key
│     └─ sensor-net.crt  / sensor-net.key
└─ logs/
   ├─ audit.log
   ├─ alerts.log
   └─ danger.log
```

## 3) Сборка (workspace)

Из корня:

```bash
cargo build --release
```

Бинарники:

```text
target/release/
```

## 4) Конфигурации (YAML)

### 4.1 analyzer.yaml (сервер)

Пример:

```yaml
listen_addr: "0.0.0.0:5000"
rules_path: "config/rules.yaml"
audit_log_path: "logs/audit.log"

tls_enabled: true
tls_require_mtls: true
tls_ca_path: "config/pki/ca.crt"
tls_cert_path: "config/pki/analyzer.crt"
tls_key_path: "config/pki/analyzer.key"
tls_server_name: "sov-analyzer"
```

### 4.2 node-sensor.yaml (узловой сенсор)

Linux:

```yaml
server_addr: "192.168.0.102:5000"
node_id: "kali-node-01"
log_paths:
  - "/var/log/syslog"
  - "/var/log/auth.log"
poll_interval_ms: 1000

tls:
  enabled: true
  ca_path: "config/pki/ca.crt"
  cert_path: "config/pki/sensor-node.crt"
  key_path: "config/pki/sensor-node.key"
  server_name: "sov-analyzer"
```

Windows (Event Log каналы):

```yaml
server_addr: "192.168.0.102:5000"
node_id: "win-node-01"
log_paths:
  - "Security"
  - "System"
  - "Application"
poll_interval_ms: 1000

tls:
  enabled: true
  ca_path: "config/pki/ca.crt"
  cert_path: "config/pki/sensor-node.crt"
  key_path: "config/pki/sensor-node.key"
  server_name: "sov-analyzer"
```

### 4.3 net-sensor.yaml (сетевой сенсор)

Linux/Kali:

```yaml
server_addr: "192.168.0.102:5000"
node_id: "kali-net-01"
iface: "eth0"
pcap_filter: "tcp"
snapshot_len: 65535
promiscuous: true

tls:
  enabled: true
  ca_path: "config/pki/ca.crt"
  cert_path: "config/pki/sensor-net.crt"
  key_path: "config/pki/sensor-net.key"
  server_name: "sov-analyzer"
```

Windows:

- `iface` должен быть в формате `\\Device\\NPF_{GUID}` (Npcap)
- список можно вывести `--list-ifaces`

### 4.4 admin-cli.yaml / operator-cli.yaml

admin:

```yaml
server_addr: "192.168.0.102:5000"
tls:
  enabled: true
  ca_path: "config/pki/ca.crt"
  cert_path: "config/pki/admin.crt"
  key_path: "config/pki/admin.key"
  server_name: "sov-analyzer"
```

operator:

```yaml
server_addr: "192.168.0.102:5000"
tls:
  enabled: true
  ca_path: "config/pki/ca.crt"
  cert_path: "config/pki/operator.crt"
  key_path: "config/pki/operator.key"
  server_name: "sov-analyzer"
```

## 5) Запуск (рекомендуемый порядок)

### 5.1 Анализатор (Arch, 192.168.0.102)

```bash
cd ~/sov
RUST_LOG=info ./target/release/sov-analyzer -c config/analyzer.yaml
```

Ожидаемо:

```text
Analyzer listening on 0.0.0.0:5000
```

### 5.2 Узловой сенсор (Kali/Linux)

```bash
cd ~/sov
sudo RUST_LOG=info ./target/release/sov-sensor-node -c config/node-sensor.yaml
```

Если нужно явно:

```bash
sudo ./target/release/sov-sensor-node -c config/node-sensor.yaml --os linux
```

### 5.3 Сетевой сенсор (Kali/Linux)

```bash
cd ~/sov
sudo RUST_LOG=info ./target/release/sov-sensor-net -c config/net-sensor.yaml
```

### 5.4 Admin CLI (можно запускать с любой машины в сети)

```bash
cd ~/sov
./target/release/sov-admin-cli -c config/admin-cli.yaml status
./target/release/sov-admin-cli -c config/admin-cli.yaml rules-push --rules config/rules.yaml
```

### 5.5 Operator CLI

```bash
cd ~/sov
./target/release/sov-operator-cli -c config/operator-cli.yaml status
./target/release/sov-operator-cli -c config/operator-cli.yaml alerts-subscribe
```

## 6) Проверка работоспособности

### 6.1 Проверка Node IDS (Linux)

Сгенерировать событие в auth.log:

```bash
ssh wronguser@localhost
```

Должно совпасть с правилом типа:

```yaml
pattern: "Failed password for"
target: "node.raw_line"
```

### 6.2 Проверка Net IDS (HTTP GET)

Важно: HTTPS payload не видно (шифр).  
Делаем обычный HTTP:

```bash
curl http://example.com/
```

Правило:

```yaml
pattern: "GET "
target: "net.payload"
```

## 7) Windows заметки

### 7.1 Node sensor

- “реальный” EventLog режим включается фичей `windows-eventlog`
- без фичи — пустышка (собирается, но событий не даёт)

### 7.2 Net sensor

Нужен Npcap + запуск от администратора.  
Интерфейс берётся из `--list-ifaces` и прописывается как:  
`\\Device\\NPF_{GUID}`

## 8) Типовые проблемы

### Сенсоры подключаются, но “ничего не происходит”

- нет совпадений правил
- трафик HTTPS (payload не виден)
- не тот интерфейс или фильтр pcap
- нет прав на чтение логов / pcap
- на Windows не установлен Npcap / не найден wpcap.lib при сборке

### libpcap не найден (Linux)

```bash
sudo apt install -y libpcap-dev
```

## 9) Примечание по ГОСТ (в учебной реализации)

- Сбор событий (узловые/сетевые) — FID_COL
- Анализ по правилам — FID_ANL
- Сигнатурный метод — FID_MTH (поддержка)
- Аудит/журналирование — FAU
- Ролевой доступ (по сертификату OU) — FMT/RBAC (учебно)
- Защита канала связи (TLS/mTLS) — защита трафика между компонентами

# Как работает проект и что запускать на каком узле

Представь, что у тебя 3 типа машин:

## 1) Сервер (Arch) — 192.168.0.102

**Запускается только:**

- `sov-analyzer`
  Он:
- слушает `0.0.0.0:5000`
- принимает подключения **сенсоров** и **CLI**
- проверяет сертификат клиента (mTLS)
- по OU определяет роль:
  - Sensor → принимает события
  - SecurityAdmin → принимает push правил
  - Operator → подписка/просмотр
- применяет `rules.yaml` к событиям
- пишет:
  - `logs/audit.log` (аудит)
  - `logs/alerts.log` (алерты)

## 2) Клиент/наблюдаемая Linux машина (Kali) — например 192.168.0.117

**Запускаются:**

- `sov-sensor-node` (читает `/var/log/auth.log`, `/var/log/syslog`)
- `sov-sensor-net` (слушает `eth0` через pcap)
  Оба подключаются к analyzer на `192.168.0.102:5000` и шлют события.
  Важно:
- `node` почти всегда нужно `sudo` (чтение логов)
- `net` почти всегда нужно `sudo` (pcap)

## 3) Windows машина (если мониторишь Windows)

**Запускаются:**

- `sov-sensor-node.exe` (Event Log, если собрано с `--features windows-eventlog`)
- `sov-sensor-net.exe` (Npcap)
  Они тоже подключаются к analyzer на том же порту.

## 4) Где запускать CLI

CLI можно запускать:

- на сервере (Arch)
- на Kali
- на любой машине в сети
  Главное:
- доступ к `192.168.0.102:5000`
- правильные сертификаты (`admin.crt/key` или `operator.crt/key`)

# Рекомендуемый порядок запуска в твоей сети

1. На Arch (192.168.0.102):

```bash
RUST_LOG=info ./target/release/sov-analyzer -c config/analyzer.yaml
```

2. На Kali:

```bash
sudo RUST_LOG=info ./target/release/sov-sensor-node -c config/node-sensor.yaml
sudo RUST_LOG=info ./target/release/sov-sensor-net  -c config/net-sensor.yaml
```

3. Проверка (на Kali):

```bash
ssh wronguser@localhost
curl http://example.com/
```

4. Мониторинг (operator cli, где удобно):

```bash
./target/release/sov-operator-cli -c config/operator-cli.yaml alerts-subscribe
```

5. Обновление правил (admin cli):

```bash
./target/release/sov-admin-cli -c config/admin-cli.yaml rules-push --rules config/rules.yaml
```
