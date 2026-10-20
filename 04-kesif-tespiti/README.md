# Aşama 4 — Keşif (Reconnaissance) Tespiti


## Keşif (reconnaissance) nedir?

**Keşif**, bir saldırının **ilk aşaması**: saldırgan hedef ağ hakkında bilgi toplar  hangi
makineler ayakta, hangi portlar açık, hangi servisler çalışıyor, sürüm ne. MITRE ATT&CK'te
**Reconnaissance** (TA0043) ve **Discovery** (TA0007) taktiklerine denk geliyor. Keşfi erken
yakalamanın, saldırıyı **daha patlamadan** fark etmek olduğunu biliyorum.

En yaygın araç **Nmap**. Tarama türleri:
- **Ping sweep** : hangi IP'ler canlı (ICMP/ARP)
- **SYN scan (`-sS`)** : "yarı açık" port taraması, hızlı ve sessiz
- **Connect scan (`-sT`)** : tam TCP el sıkışması, log'da daha görünür
- **Version/OS detection (`-sV`, `-O`)** : servis sürümü / işletim sistemi tahmini

## Anahtar terimler

| Terim | Anlamı |
|-------|--------|
| **Port scan** | Hangi portların açık olduğunu tarama |
| **SYN/half-open** | El sıkışmayı tamamlamadan tarama (iz az) |
| **Fan-out** | Tek kaynağın kısa sürede çok hedefe/porta bağlanması (tespit sinyali) |
| **IDS/IPS** | Ağ tabanlı saldırı tespit/engelleme sistemi |

## Bu aşamayı neden erteledim?

Port taraması **ağ seviyesinde** bir olay. En iyi tespitini, trafiği gören bir **ağ cihazı**
(firewall/IDS) yapıyor. Benim labım **bridge** modunda olduğu için FortiGate inline (trafiğin
önünde) duramıyor; bu yüzden keşif tespitini **Aşama 10'da FortiGate loglarıyla** ele almayı daha
anlamlı buldum. Uç nokta (Wazuh agent) tek bir makinedeki bağlantıları görüyor ama ağ genelindeki
tarama desenini göremiyor.

## İleride ne yapacağım (plan)

1. Kali'den Nmap ile lab ağını tarayacağım (`nmap -sS -sV 192.168.1.0/24`).
2. Tespiti iki açıdan deneyeceğim:
   - **FortiGate logları** → kısa sürede çok porta bağlantı (fan-out) deseni.
   - **Uç nokta** → tek makinede çok sayıda reddedilen bağlantı (Windows Filtering Platform / 5156-5157).
3. "Tek kaynak → N farklı porta < T saniyede" korelasyon kuralı yazacağım.

## SOC / mavi takım gözüyle

- Keşif tek başına "kritik" değil ama **saldırının habercisi**  context için logluyorum.
- İç ağda **beklenmedik bir makinenin** tarama yapması (örn. bir istemciden tüm ağa SYN) benim için
  güçlü bir uzlaşma (compromise) göstergesi.

---
