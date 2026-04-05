# Prompt analityczny — Net Monitor

Uzywaj tego prompta w Claude Code / Claude Cowork do analizy logow z `~/.net_monitor/`.

---

## Instrukcja dla Claude

Przeanalizuj dane z monitoringu sieci w `~/.net_monitor/`. Twoj cel: przygotowac twarde dowody na problemy z ISP.

### Krok 1: Wczytaj dane

Kazda sesja monitoringu tworzy osobny katalog w `~/.net_monitor/output/`.
Wylistuj katalogi sesji i dla kazdej (lub najnowszej) przeczytaj:

1. **`connection_info.json`** — konfiguracja polaczenia zapisana na starcie sesji.
   Zawiera: typ interfejsu (WiFi/Ethernet), IP, gateway, DNS, WiFi SSID/RSSI/channel/PHY,
   kontrargumenty ISP z ocena ryzyka.

2. **`events.jsonl`** — glowne zrodlo danych. Kazda linia to JSON event.
   - `session_start` — konfiguracja sieci, argumenty ISP, parametry testu
   - `cycle_start` — stan sieci w momencie cyklu (wykrywa zmiany sieci!)
   - `trace_cycle` — wyniki per target: ile run OK, ile fail, na ktorym hopie odpadlo
   - `drop_start` / `drop_end` — poczatek/koniec pelnych przerw z fault_zone
   - `session_end` — podsumowanie sesji

3. **`traceroute_raw.log`** — surowe wyniki traceroute (do weryfikacji)

4. **`incidents_log.csv`** — incydenty z fault_zone i detalami

5. **`drops_log.csv`** — pelne przerwy z czasem trwania

### Krok 2: Analiza

Odpowiedz na pytania:

#### A. Profil problemu
- Kiedy wystepuja problemy? (godziny, pattern czasowy)
- Jak czesto? (% cykli z bledami)
- Jak dlugo trwaja przerwy?
- Czy problem jest ciagly czy intermittentny?

#### B. Lokalizacja usterki
- Na ktorym hopie najczesciej odpadaja pakiety?
- Jaka jest strefa usterki (LOCAL / ISP_EDGE / ISP_CORE / TRANSIT)?
- Czy hop 1 (router klienta) jest stabilny? (to kluczowe — eliminuje argument ISP)
- Czy problem jest powtarzalny na obu celach (google_dns + cloudflare_dns)?

#### C. Konfiguracja sieci
- Jaki typ polaczenia (WiFi/Ethernet)?
- Jesli WiFi: jaki sygnal (RSSI), kanal, PHY mode?
- Czy konfiguracja sieci sie zmieniala w trakcie monitoringu?
- Czy DNS/gateway sa prawidlowe?

#### D. Kontrargumenty ISP
- Przejrzyj `isp_counterarguments` z `session_start` event
- Czy dane potwierdzaja nasze rebuttals?
- Czy sa jakies slabe punkty w naszej argumentacji?

### Krok 3: Raport

Napisz krotki raport w formie:

```
## Diagnoza

[1-3 zdania: co sie dzieje, gdzie jest problem]

## Dowody

- Hop 1 (LOCAL): [stabilny/niestabilny] — [dane]
- Hop 2 (ISP_EDGE): [stabilny/niestabilny] — [dane]
- Pattern czasowy: [opis]
- Powtarzalnosc: [na ilu celach]

## Kontrargumenty ISP

| Argument ISP | Nasza odpowiedz | Sila dowodu |
|---|---|---|
| "Problem z WiFi" | Hop 1 = 0% loss, RSSI -65dBm | Silny |
| "Problem z routerem" | Hop 1 stabilny, problem od hop 2 | Silny |
| ... | ... | ... |

## Rekomendacja

[Co robic dalej: reklamacja / UKE / zmiana dostawcy]
[Jesli dane sa niewystarczajace: co jeszcze zebrac]
```

### Krok 4: Jesli dane sa niewystarczajace

Jesli logow jest za malo lub nie widac wyraznego patternu:
- Powiedz wprost co brakuje
- Zasugeruj jak dlugo jeszcze monitorowac
- Zaproponuj dodatkowe testy (np. Ethernet zamiast WiFi, inna pora dnia)
