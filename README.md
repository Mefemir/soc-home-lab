# SOC Ev Lab

Active Directory, Wazuh SIEM ve FortiGate'ten oluşan bir ev laboratuvarında
**saldırı simülasyonu ve tespit (detection) çalışmaları**.

Bu depo bir öğrenme ve portföy projesidir: her aşamada bir saldırı yapılır,
saldırının loglarda bıraktığı iz bulunur ve o izi yakalayan tespit kuralı yazılır.
Amaç, SOC analisti bakış açısıyla **saldırı → log → tespit** döngüsünü kanıtlamaktır.

## Mimari

![Lab topolojisi](00-temel-ve-mimari/gorseller/topoloji.png)

> Topoloji diyagramını `00-temel-ve-mimari/gorseller/topoloji.png` altına ekle
> (draw.io ile çizilebilir).

## Ortam

| Rol | Sistem | Not |
|-----|--------|-----|
| Domain Controller | Windows Server 2019 | AD DS + DNS |
| İstemci | Windows 10 | Domain üyesi |
| SIEM | Wazuh | Log toplama + tespit |
| Saldırgan | Kali Linux 2025.2 | Saldırı araçları |
| Çevre | FortiGate | Log kaynağı (bkz. Aşama 10) |

**Ağ modu:** Bridged — tüm makineler ev ağından (`192.168.1.0/24`) IP alır.
Ayrıntılı IP planı ve bridge'in getirdiği uyarılar için
[00 - Temel ve Mimari](00-temel-ve-mimari/) bölümüne bak.

## İçindekiler

- [00 - Temel ve Mimari](00-temel-ve-mimari/)
- [01 - Active Directory](01-active-directory/)
- [02 - Wazuh SIEM](02-wazuh-siem/)
- [03 - Loglama ve Sysmon](03-loglama-sysmon/)
- [04 - Keşif Tespiti](04-kesif-tespiti/)
- [05 - Brute-force Tespiti](05-brute-force/)
- [06 - Active Directory Saldırıları](06-ad-saldirilari/)
- [07 - Post-exploitation](07-post-exploitation/)
- [08 - MITRE ATT&CK ve Detection Engineering](08-mitre-attack/)
- [09 - Olay Müdahalesi](09-olay-mudahalesi/)
- [10 - FortiGate Entegrasyonu](10-fortigate/)

## Durum

| Aşama | Durum |
|-------|-------|
| 00 - Temel ve Mimari | 🟡 Devam ediyor |
| 01-10 | ⚪ Beklemede |

---
*Bu lab eğitim amaçlıdır. Tüm saldırılar yalnızca kendi izole/ev laboratuvarımda,
kendi sistemlerime karşı yapılmıştır.*
