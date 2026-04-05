# Net Monitor — Specyfikacja projektu (v2)

## 1. Cel projektu

Narzedzie CLI do ciaglego monitorowania jakosci polaczenia internetowego, ktore zbiera twarde dowody na niestabilnosc uslugi ISP. Kluczowa wartosc: **hop-by-hop diagnostyka TTL-based** pozwalajaca jednoznacznie wskazac, czy problem lezy po stronie klienta (router/WiFi) czy dostawcy (ich infrastruktura sieciowa).

Wynik koncowy: raport w formacie Markdown (po polsku) gotowy do zalaczenia do reklamacji u ISP, skargi do UKE lub odstapienia od umowy.

## 2. Kontekst uzycia

- Uzytkownik doswiadcza intermittentnych przerw w lacznosci
- ISP typowo odrzuca reklamacje argumentami: "nie jest na kablu", "router wadliwy", "po naszej stronie wszystko OK"
- Narzedzie musi dostarczyc dane, ktore te argumenty eliminuja — szczegolnie dowod, ze hop 1 (router klienta) dziala stabilnie, a problem zaczyna sie na hop 2+ (infrastruktura ISP)
- Dodatkowe zbieranie info o konfiguracji polaczenia (WiFi RSSI, kanal, PHY mode, typ interfejsu) eliminuje argumenty ISP o "slabym WiFi"

## 3. Architektura

### 3.1. Jeden plik Python (`net_monitor.py`), zero pip dependencies

Korzysta z: `traceroute`, `ping`, `curl` (systemowe) + Python stdlib.

### 3.2. Struktura danych — per-session output

Kazdy start monitoringu tworzy nowy katalog sesji:

```
~/.net_monitor/
  output/
    20260405_143000/              # <-- sesja z 2026-04-05 14:30:00
      connection_info.json        # konfiguracja polaczenia + kontrargumenty ISP
      events.jsonl                # AI-friendly event stream (glowny plik do analizy)
      traceroute_raw.log          # surowe wyniki traceroute (surowka)
      hop_log.csv                 # per-hop reached/failed per cykl
      incidents_log.csv           # incydenty z fault_zone
      drops_log.csv               # pelne przerwy z czasem trwania
      speed_log.csv               # testy predkosci
    20260405_180000/              # <-- nastepna sesja
      ...
  reports/                        # generowane raporty JSON + Markdown
```

### 3.3. connection_info.json

Zapisywany na starcie kazdej sesji. Zawiera:

```json
{
  "session_start": "2026-04-05T14:30:00",
  "hostname": "macbook-pro",
  "platform": "darwin",
  "network": {
    "interface": "en0",
    "interface_type": "wifi",
    "ip": "192.168.1.136",
    "subnet": "255.255.255.0",
    "gateway": "192.168.1.1",
    "dns_servers": ["192.168.1.1"],
    "mac": "14:14:7d:96:04:80",
    "mtu": "1500",
    "wifi_ssid": "HomeNetwork",
    "wifi_rssi_dbm": -65,
    "wifi_noise_dbm": -94,
    "wifi_channel": "48 (5GHz, 80MHz)",
    "wifi_phy_mode": "802.11ac",
    "wifi_tx_rate": "867",
    "wifi_security": "WPA2 Personal"
  },
  "isp_counterarguments": [
    {
      "isp_argument": "Uzywasz WiFi, problem moze byc w zasiegu",
      "our_data": "Signal: -65dBm, Channel: 48 (5GHz)",
      "rebuttal": "Hop 1 = 0% loss, RSSI w normie",
      "risk": "low"
    }
  ],
  "monitor_config": {
    "trace_targets": {"google_dns": "8.8.8.8", "cloudflare_dns": "1.1.1.1"},
    "ping_targets": {"google_web": "google.com", ...},
    "runs_per_target": 10,
    "max_hops": 15,
    "loss_threshold": 5.0
  }
}
```

### 3.4. events.jsonl — AI-friendly event stream

Kazda linia to JSON event z `ts` i `type`:

| Event type | Opis | Kluczowe pola |
|---|---|---|
| `session_start` | Start sesji | network_env, isp_counterarguments, config |
| `cycle_start` | Poczatek cyklu | cycle, network_env (snapshot) |
| `traceroute` | Odkrycie trasy | target, hops |
| `trace_cycle` | Wyniki prob per target | ok, fail, faults [{hop_num, host, zone}] |
| `drop_start` | Poczatek przerwy | fault_zone, detail |
| `drop_end` | Koniec przerwy | duration_seconds, fault_zone |
| `cycle_end` | Podsumowanie cyklu | ok, fail, pings_ok |
| `speed_test` | Test predkosci | speed_mbps |
| `session_end` | Koniec sesji | total stats |

## 4. Tryb monitorowania — TTL-based progressive tracing

### 4.1. Cykl monitorowania

```
loop (ciagly, bez przerw miedzy cyklami):
  1. Zbierz network env (WiFi signal, interface, IP, gateway)
  2. Dla kazdego TRACE_TARGET:
     a. traceroute — odkryj trase (hops)
     b. N probe runs:
        - Kazdy run = 1 pakiet z rosnacym TTL (1, 2, 3, ...)
        - Na kazdym hopie: pakiet przechodzi (TTL exceeded) lub odpada (timeout)
        - Jesli osiagnie cel: run OK
        - Jesli timeout na hopie: run FAIL, zapisz ktory hop
        - Real-time display: kazdy hop = 1 dot na linii
     c. Podsumowanie: X/N OK, faults per zone
  3. Quick ping targets (google.com, cloudflare.com, amazon.com)
  4. Drop detection (all unreachable = drop)
  5. Periodyczny speed test
```

### 4.2. Display — append mode, ANSI colors

```
[14:30:00] google_dns (8.8.8.8) | 8 hops | 10 runs
  route: 192.168.1.1 > 10.0.0.1 > 72.14.215.85 > ... > 8.8.8.8
  #1   ●●●●●●●●  ✓ 14ms
  #2   ●●○        ✗ hop 3 [ISP_CORE] 72.14.215.85
  #3   ●●●●●●●●  ✓ 13ms
  #4   ●○         ✗ hop 2 [ISP_EDGE] 10.0.0.1
  #5   ●●●●●●●●  ✓ 15ms
  ...
  8/10 OK (80%)  | faults: ISP_EDGE:1 ISP_CORE:1
```

Kazdy `●` = 1 hop przeszedl. `○` = pakiet odpadl na tym hopie. Linia buduje sie live.

### 4.3. Podsumowanie sesji (Ctrl+C)

Zawiera:
- Cykle testowe, czas trwania, uptime
- Tabela stref usterek (ilosc + udzial %)
- **Tabela per-hop** (przeszlo / odpadlo / % bledow) — kluczowe
- Rozbicie bledow per strefa z histogramem
- Sciezki do plikow sesji

### 4.4. Zmiana sieci

Jesli w trakcie cyklu zmieni sie interface, SSID, IP lub gateway — wyswietl ostrzezenie i zaloguj zmiane. Pozwala korelowac problemy ze zmiana sieci.

## 5. Zbieranie informacji o polaczeniu

### 5.1. Co zbieramy (macOS + Linux)

| Dane | macOS | Linux |
|---|---|---|
| Aktywny interface | `route -n get default` | `ip route show default` |
| IP/subnet/gateway | `ifconfig`, `route` | `ip addr show` |
| DNS | `scutil --dns` | `/etc/resolv.conf` |
| Typ interfejsu | `networksetup -listallhardwareports` | `iw dev` / `ethtool` |
| WiFi SSID, RSSI, channel | `system_profiler SPAirPortDataType` | `iw dev <iface> info/link` |
| WiFi PHY mode, tx rate | j.w. | j.w. |
| Ethernet media | `ifconfig` (media line) | `ethtool` |

### 5.2. Kontrargumenty ISP

Na podstawie konfiguracji automatycznie generujemy liste:

| Argument ISP | Nasza odpowiedz |
|---|---|
| "Problem z WiFi" | Hop 1 = 0% loss, RSSI w normie, WiFi dziala |
| "Problem z routerem" | Hop 1 stabilny, problem od hop 2 |
| "Problem z DNS" | Testy uzywaja ICMP po IP, DNS nie wplywa |
| "Kabel wadliwy" (Ethernet) | Hop 1 = 0% loss, kabel OK |

## 6. Raportowanie

### 6.1. `--report` generuje raport z WSZYSTKICH sesji

Skanuje wszystkie katalogi w `output/`, agreguje dane, generuje:
- JSON z pelnymi statystykami
- Markdown po polsku gotowy do reklamacji

### 6.2. Analiza z Claude Code / Cowork

Plik `analyze_prompt.md` zawiera gotowy prompt analityczny. Uzycie:

```
# W Claude Code, w katalogu projektu:
Przeanalizuj logi z ~/.net_monitor/ uzywajac prompta z analyze_prompt.md
```

Claude przeczyta `events.jsonl` + `connection_info.json` z kazdej sesji i przygotuje diagnoze z kontrargumentami ISP.

## 7. Konfiguracja

| Parametr | Wartosc | Opis |
|---|---|---|
| `TRACE_TARGETS` | google_dns: 8.8.8.8, cloudflare_dns: 1.1.1.1 | Cele traceroute |
| `PING_TARGETS` | google.com, cloudflare.com, amazon.com | Cele ping |
| `RUNS_PER_TARGET` | 10 | Prob per target per cykl |
| `MAX_HOPS` | 15 | Max TTL |
| `PAUSE_BETWEEN_RUNS` | 1.0s | Min przerwa miedzy probami |
| `LOSS_THRESHOLD` | 5.0% | Prog loss = problem |
| `SPEED_TEST_INTERVAL` | 900s | Co ile test predkosci |

## 8. Zaleznosci

| Zaleznosc | Typ | Instalacja |
|---|---|---|
| Python 3.8+ | Runtime | Preinstalowany |
| `traceroute` | System | Preinstalowany (macOS/Linux) |
| `ping` | System | Preinstalowany |
| `curl` | System | Preinstalowany |

Brak pip dependencies. Brak `mtr` (zamieniony na `traceroute` + TTL-based `ping`).

## 9. Edge cases

| Scenariusz | Zachowanie |
|---|---|
| Brak traceroute | Czytelny komunikat |
| Brak sieci przy starcie | Loguje timeout, nie crashuje |
| Hop ??? (brak ICMP) | Pomijany w analizie |
| Ctrl+C | Graceful shutdown + podsumowanie |
| Zmiana sieci w trakcie | Wykryta i zalogowana |
| Brak danych przy --report | Czytelny komunikat |

## 10. Pliki projektu

```
net_monitor/
  net_monitor.py         # glowny plik (jedyny kod)
  SPEC.md                # ta specyfikacja
  CLAUDE.md              # kontekst dla Claude Code
  analyze_prompt.md      # prompt analityczny dla Claude Cowork
```
