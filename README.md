# SOV — учебная система обнаружения вторжений (Node + Network IDS)

Проект написан на Rust и состоит из:
- центрального анализатора,
- узлового сенсора (Linux / Windows),
- сетевого сенсора (pcap),
- CLI для администрирования и оператора.
## 2. Структура проекта
```text
sov/
├─ Cargo.toml            # workspace
├─ sov-core/             # общие типы, события, правила
├─ sov-transport/        # TCP-протокол обмена
├─ sov-analyzer/         # центральный анализатор
├─ sov-sensor-node/      # узловой сенсор (Linux / Windows)
├─ sov-sensor-net/       # сетевой сенсор (pcap)
├─ sov-admin-cli/        # CLI администратора
├─ sov-operator-cli/     # CLI оператора
├─ config/               # YAML-конфигурации
└─ logs/                 # аудит и алерты
```
## 3. Сборка всего проекта (workspace)
Из корня проекта:
```bash
cargo build --release
```
Бинарники появятся в:
```text
target/release/
```
## 4. Анализатор (sov-analyzer)
### Сборка
```bash
cargo build --release -p sov-analyzer
```
### Запуск (Linux / Windows)

```bash
./target/release/sov-analyzer -c config/analyzer.yaml
```
Ожидаемый вывод:
```text
Analyzer listening on 0.0.0.0:5000
```
## 5. Узловой сенсор (sov-sensor-node)
Один бинарник:
- Linux → читает `/var/log/*`
- Windows → читает Windows Event Log
- выбор через `--os` или автоматически
### 5.1 Linux
#### Требования
- права на чтение логов (обычно `sudo`)
- наличие `/var/log/auth.log`, `/var/log/syslog` или аналогов
#### Сборка
```bash
cargo build --release -p sov-sensor-node
```
#### Запуск (автоопределение ОС)
```bash
sudo ./target/release/sov-sensor-node -c config/node-sensor.yaml
```
#### Принудительно
```bash
sudo ./target/release/sov-sensor-node -c config/node-sensor.yaml --os linux
```
### 5.2 Windows (узловой сенсор)
#### Режимы

| Режим    | Как собрать                   | Что делает       |
| -------- | ----------------------------- | ---------------- |
| Пустышка | без фич                       | ничего не читает |
| Реальный | `--features windows-eventlog` | читает Event Log |

#### Сборка (пустышка)
```powershell
cargo build -p sov-sensor-node
```
#### Сборка (реальный Event Log)
```powershell
cargo build -p sov-sensor-node --features windows-eventlog
```
#### Запуск
```powershell
.\target\release\sov-sensor-node.exe -c config\node-sensor.yaml
```
или явно:
```powershell
.\target\release\sov-sensor-node.exe -c config\node-sensor.yaml --os windows
```
#### Конфиг для Windows (`node-sensor.yaml`)
```yaml
server_addr: "192.168.0.102:5000"
node_id: "win-node-01"
log_paths:
  - "Security"
  - "System"
  - "Application"
poll_interval_ms: 1000
```

## 6. Сетевой сенсор (sov-sensor-net)
### 6.1 Linux / Kali
#### Требования
- `libpcap-dev`
- root / sudo
Установка:
```bash
sudo apt install -y libpcap-dev
```
#### Сборка
```bash
cargo build --release -p sov-sensor-net
```
#### Запуск
```bash
sudo ./target/release/sov-sensor-net -c config/net-sensor.yaml
```
#### Пример `net-sensor.yaml`
```yaml
server_addr: "192.168.0.102:5000"
node_id: "kali-net"
iface: "eth0"
pcap_filter: "tcp"
snapshot_len: 65535
promiscuous: true
```

> `iface` — сетевой интерфейс машины, где запущен сенсор  
> (проверь через `ip a`).

---
### 6.2 Windows (сетевой сенсор)
#### Требования
- **Npcap**
- режим совместимости с WinPcap
- запуск от администратора
#### Интерфейс
Интерфейс указывается как:
```text
\Device\NPF_{GUID}
```
Получить список можно через:
```rust
pcap::Device::list()
```
## 7. Проверка работоспособности
### 7.1 Node IDS (Linux)
```bash
ssh wronguser@localhost
```
Проверить:
```bash
sudo grep "Failed password" /var/log/auth.log
```
Должен появиться алерт.
### 7.2 Network IDS (HTTP GET)
```bash
curl http://<server-ip>:8080/
```
При наличии правила:
```yaml
pattern: "GET "
target: "net.payload"
```
будет сгенерирован алерт.
## 8. Типовые проблемы
### Нет алертов
- нет совпадений с правилами
- не тот интерфейс (`iface`)
- HTTPS вместо HTTP
- нет прав на логи / pcap

### `libpcap` не найден

```text
unable to find library -lpcap
```
Решение:
```bash
sudo apt install libpcap-dev
```
## 9. Полезные команды
### Сборка одного компонента

```bash
cargo build -p sov-analyzer
cargo build -p sov-sensor-node
cargo build -p sov-sensor-net
```
### Очистка
```bash
cargo clean
```
## 10. Примечание по ГОСТ
Реализация демонстрирует:
- сбор событий (FID_COL),
- анализ (FID_ANL),
- сигнатурный метод (FID_MTH),
- аудит (FAU),
- ролевую модель (FMT).