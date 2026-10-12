# Aşama 4 — Keşif (Reconnaissance) Tespiti

> ⏸ Ertelendi — bridge modunda en doğru yeri ağ/FortiGate katmanı (bkz. [Aşama 10](../10-fortigate/)).

## Keşif (reconnaissance) nedir?

**Keşif**, bir saldırının **ilk aşamasıdır**: saldırgan hedef ağ hakkında bilgi toplar —
hangi makineler ayakta, hangi portlar açık, hangi servisler çalışıyor, sürüm nedir.
MITRE ATT&CK'te **Reconnaissance** (TA0043) ve **Discovery** (TA0007) taktiklerine denk gelir.
Keşfi erken yakalamak, saldırıyı **daha patlamadan** fark etmek demektir.

En yaygın araç **Nmap**'tir. Tarama türleri:
- **Ping sweep** — hangi IP'ler canlı (ICMP/ARP)
- **SYN scan (`-sS`)** — "yarı açık" port taraması, hızlı ve sessiz
- **Connect scan (`-sT`)** — tam TCP el sıkışması, log'da daha görünür
- **Version/OS detection (`-sV`, `-O`)** — servis sürümü / işletim sistemi tahmini

## Anahtar terimler

| Terim | Anlamı |
|-------|--------|
| **Port scan** | Hangi portların açık olduğunu tarama |
| **SYN/half-open** | El sıkışmayı tamamlamadan tarama (iz az) |
| **Fan-out** | Tek kaynağın kısa sürede çok hedefe/porta bağlanması (tespit sinyali) |
| **IDS/IPS** | Ağ tabanlı saldırı tespit/engelleme sistemi |

## Bu aşama neden ertelendi?

Port taraması **ağ seviyesinde** bir olaydır. En iyi tespiti, trafiği gören bir
**ağ cihazı** (firewall/IDS) yapar. Bizim labımız **bridge** modunda olduğu için
FortiGate inline (trafiğin önünde) duramıyor; bu yüzden keşif tespitini **Aşama 10'da
FortiGate loglarıyla** ele almak daha anlamlı. Uç nokta (Wazuh agent) tek bir makinedeki
bağlantıları görür ama ağ genelindeki tarama desenini göremez.

## İleride ne yapacağız (plan)

1. Kali'den Nmap ile lab ağını tarayacağız (`nmap -sS -sV 192.168.1.0/24`).
2. Tespiti iki açıdan deneyeceğiz:
   - **FortiGate logları** → kısa sürede çok porta bağlantı (fan-out) deseni.
   - **Uç nokta** → tek makinede çok sayıda reddedilen bağlantı (Windows Filtering Platform / 5156-5157).
3. "Tek kaynak → N farklı porta < T saniyede" korelasyon kuralı.

## SOC / mavi takım gözüyle

- Keşif tek başına "kritik" değildir ama **saldırının habercisidir** — context için loglanır.
- İç ağda **beklenmedik bir makinenin** tarama yapması (örn. bir istemciden tüm ağa SYN)
  güçlü bir uzlaşma (compromise) göstergesidir.

---