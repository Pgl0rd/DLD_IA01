# Sensor Layer 1 (DLP)

Implementacao de producao para Layer 1 com:

- Unified Event Schema padronizado
- 7 sensores modulares (file, clipboard, process, network, usb, print, browser_upload)
- Emissao em tempo real para fila confiavel
- Retry + offline buffering criptografado
- Estrutura config-driven
- Sensores rodando em loop continuo (sem payload fake)

## Arquitetura de Fluxo (L1 → L2 → L3)

```
L1  Browser Extension (content.js)
        │ File Input / Drag-Drop / XHR watcher
        ▼
    background.js  ──→  Native Messaging Host (native_host/native_host.py)
                                │ Named Pipe: \\.\pipe\dlp_browser_upload
                                ▼
    BrowserUploadSensor  ←──────┘
    FileSensor  ─────────────────────────────╮
    NetworkSensor  ──────────────────────────┤
                                             ▼
                        Sensor Logic / Event Correlator / Upload Context Resolver
                         (UploadCorrelatorPublisher + BrowserUploadContextResolver)
                                             │
                                             ▼
L2  Secure IPC Queue  (ReliableEventQueue + encrypted buffer)
                                             │
                                             ▼
L3  Detection Engine  (rule match / scan / OCR / risk scoring)
```

Event types emitidos:

| Type | Source | Description |
|---|---|---|
| `browser_upload` | browser_upload_sensor | Upload raw từ extension |
| `corr_browser_upload` | correlator | Upload đã resolve local path |
| `network_outbound_candidate` | network_sensor | Candidate outbound |
| `corr_suspected_upload` | correlator | Network + file correlated |

## Requisitos

- Python 3.10+
- Dependencias:

```bash
pip install -r requirements.txt
```

## Execucao

```bash
python -m sensor_system.runner
```

Cada linha de saida e um evento JSON no schema unificado, gerado por atividade real do sistema.

## Testar sensor individual

Rodar apenas um sensor:

```bash
python -m sensor_system.runner --sensor process_sensor
```

Exemplos:

```bash
python -m sensor_system.runner --sensor file_sensor --watch-path C:\PRJ\ProjectIA\Sensor
python -m sensor_system.runner --sensor clipboard_sensor
python -m sensor_system.runner --sensor network_sensor
python -m sensor_system.runner --sensor usb_sensor
python -m sensor_system.runner --sensor print_sensor
python -m sensor_system.runner --sensor browser_upload_sensor
```

Rodar varios sensores especificos:

```bash
python -m sensor_system.runner --sensor process_sensor --sensor network_sensor
# Browser Upload + File + Network (fluxo completo L1)
python -m sensor_system.runner --sensor browser_upload_sensor --sensor file_sensor --sensor network_sensor
```

## Configurar Browser Upload Sensor

### 1. Instalar Chrome Extension

1. Abrir `chrome://extensions`
2. Ativar **Developer Mode**
3. Clicar em **Load unpacked** → selecionar pasta `browser_extension/`
4. Copiar o **Extension ID** exibido

### 2. Registrar Native Host no Windows

```bash
# Editar browser_extension/manifest.json e substituir REPLACE_WITH_YOUR_EXTENSION_ID
# Depois registrar no registry:
python native_host/install_host.py

# Para Edge tambem:
python native_host/install_host.py --browser edge

# Para desinstalar:
python native_host/install_host.py --uninstall
```

### 3. Rodar sensor

```bash
python -m sensor_system.runner --sensor browser_upload_sensor
```

Ao fazer upload de arquivo no browser, surgira evento JSON:

```json
{
  "type": "browser_upload",
  "source": "browser_upload_sensor",
  "severity": "medium",
  "actor": { "user": "john", "process": "chrome" },
  "network": { "dest_domain": "drive.google.com" },
  "browser_upload": {
    "filename": "report.xlsx",
    "size": 204800,
    "tab_url": "https://drive.google.com/...",
    "trigger": "file_input",
    "confidence_score": 0.85,
    "local_path": null
  }
}
```

Se o FileSensor tiver visto o arquivo recentemente, o Correlator emite tambem:

```json
{ "type": "corr_browser_upload", "browser_upload": { "local_path": "C:\\Users\\john\\Documents\\report.xlsx", "confidence_score": 0.91 }, "rule": { "rule_name": "Browser_Upload", "severity": "high" } }
```

## Correlation event

Runtime co the emit them event bo sung:

- `corr_suspected_upload`

Event nay duoc tao khi co `network_outbound_candidate` va tim thay file event gan thoi diem trong cua so correlator.
Correlator danh gia theo Rule 3:

- upload candidate (`network_outbound_candidate` hoac host_bytes_sent_delta lon)
- external destination/tool family (browser/desktop upload app/cli upload tool/domain)
- sensitive file evidence (sensitivity hoac sensitive extension)

Khi thoa Rule 3, event se co them:

- `rule.rule_name = Network_Upload`
- `rule.severity = high`
- `rule.dest_domain`, `rule.dest_app`, `rule.bytes_out`, `rule.file_path`, `rule.sensitivity`
- `debug.evidence.recent_staging`

## Network outbound candidate sensor (honest semantics)

`network_sensor` emite apenas `network_outbound_candidate` com `operation.op_type = outbound_candidate`.

- **Nao** detecta upload de arquivo por si so; use correlator L2/L3.
- `host_bytes_sent_total` / `host_bytes_sent_delta` sao **somente contadores do host** (psutil), nunca por processo/conexao.
- `metrics.bytes_out` permanece `null` neste sensor.
- `dest_domain` vem de PTR/reverse-DNS quando disponivel — evidencia **fraca** (CDN/infra comum); veja `network.domain_confidence`.
- `recent_open_file_guess` e heuristico e so aceita paths sob raizes de usuario configuradas; caso contrario `null`.

Configuracao: `AppConfig.network_sensor_config` (`NetworkSensorConfig`) — limiares, listas deny/allow, dedup.

### Tabela de campos (network + debug)

| Field | Fonte | Confianca | Nivel |
| --- | --- | --- | --- |
| `type` | sensor | alta | evento |
| `operation.op_type` | sensor (`outbound_candidate`) | alta | evento |
| `network.host_bytes_sent_total` | psutil net_io_counters (host) | alta | **host** |
| `network.host_bytes_sent_delta` | delta entre polls (host) | alta | **host** |
| `network.dest_ip` | psutil connection raddr | alta | conexao |
| `network.dest_domain` | socket.gethostbyaddr (PTR) | baixa–media | conexao (DNS reverso) |
| `network.domain_confidence` | heuristica (infra CDN/AWS etc.) | — | meta |
| `network.recent_open_file_guess` | open_files + filtros usuario | baixa–media | **heuristica** |
| `network.file_guess_confidence` | none/low/medium | — | meta |
| `network.method` / `content_type` | nao observavel nesta stack | n/a | null |
| `debug.evidence.*` | agregado para correlator | ver payload | debug |

## Observacoes de design

- O schema base e estrito e inclui extensoes de sensor (`clipboard`, `network`, `print`) exigidas no documento.
- Todos os campos ausentes sao preenchidos com `null` quando aplicavel.
- Strings sao normalizadas para lowercase, exceto paths.
- Nao ha payload de demonstracao nas classes de producao.
- Integracoes nao finalizadas devem permanecer separadas em stubs explicitos sem emissao fake.
- `print_sensor` esta marcado como stub de producao ate integrar spooler nativo.

