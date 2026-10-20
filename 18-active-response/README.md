# Aşama 18 — Active Response (Otomatik Tepki)

> ✅ Tamamlandı  Wazuh Active Response ile **brute-force saldırısına makine hızında otomatik
> tepkiyi** canlı doğruladım. Kali (`192.168.1.105`) manager'ın SSH'ına brute-force yaptı →
> kural **5712** (level 10) tetiklendi → `firewall-drop` saldırganın IP'sini **iptables'ta
> bloklayıp** (`add`) **180 sn sonra otomatik kaldırdı** (`delete`). Beyaz liste (yönetim IP'si)
> ve stateful timeout ile **self-DoS'a karşı güvenli** tasarımı gösterdim. Bu aşama, Aşama 17'de
> işaret ettiğim *"FIM tespit eder ama tepki vermez"* boşluğunu kapatıyor.

## Active Response nedir?

Önceki tüm aşamalar **tespit + alarm** üretti bir **insan** (SOC analisti) gelip bakana kadar
sistem bekliyordu. Ama saldırgan beklemez: brute-force alarmı düşerken saldırgan saniyede onlarca
parola denemeye devam eder. **Active Response (AR)**, bir alarm tetiklendiğinde Wazuh'un
**otomatik bir komut/script çalıştırmasıdır** tespit ile müdahale arasındaki boşluğu makine
hızında kapatır.

> AR'ı, önceki aşamalardaki **görünürlüğün** üstüne eklediğim **eylem** katmanı olarak görüyorum.
> Aşama 17'de "FIM sadece tespit eder, geri almaz" demiştim işte o eylemi ekleyen mekanizma bu.

## Nasıl çalışır? (zincir)

```
Olay → Kural tetiklenir (5712 brute-force, level 10)
          → Wazuh "bu kural AR tetikler mi?" diye bakar
          → KOMUT çalışır (firewall-drop)  NEREDE? location: local/server/all
          → Saldirgan IP'si firewall'da DROP  (command: add)
          → timeout sonra otomatik GERI AL   (command: delete)
```

İki parça tanımlanır (`/var/ossec/etc/ossec.conf`):

| Blok | Görevi |
|------|--------|
| **`<command>`** | **Ne çalışacak?** Bir script'e isim verir (`firewall-drop`) |
| **`<active-response>`** | **Ne zaman + nerede + ne kadar?** Tetikleyici kural/grup, konum, timeout |

## Kullandığım yapılandırma

Wazuh'ta hazır gelen `firewall-drop` AR'ını kullandım; demo için timeout'u 600→**180 sn** indirdim
(otomatik geri açılmayı seans içinde görebilmek için).

```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_group>authentication_failures</rules_group>
  <timeout>180</timeout>
</active-response>
```

| Satır | Anlamı |
|-------|--------|
| `<command>firewall-drop</command>` | Hazır script: saldırgan IP'sini OS firewall'ında (iptables/netsh) DROP'lar |
| `<location>local</location>` | Olayı yaşayan makinede çalışır (burada: olay manager'ın kendi sshd'sinden, agent 000) |
| `<rules_group>authentication_failures</rules_group>` | **Tetikleyici:** bu gruptaki brute-force kuralları (5712/5763/5720  level 10). **Tek başarısız giriş (5710) değil**, sadece agregeli brute-force → yüksek güven, düşük FP |
| `<timeout>180</timeout>` | **Stateful:** blok geçici; 180 sn sonra otomatik kalkar |

**Beyaz liste (güvenlik ağı)** `<global>` içinde, AR'ın **asla** bloklamayacağı IP'ler:
```xml
<white_list>127.0.0.1</white_list>
<white_list>192.168.1.108</white_list>   <!-- yonetim istasyonu: asla bloklanmasin -->
```

## Hazır AR script'leri (kutudan çıkan)

| Script | Ne yapar |
|--------|----------|
| `firewall-drop` | Saldırgan IP'sini iptables/netsh ile bloklar (kullandığım) |
| `host-deny` | IP'yi `/etc/hosts.deny`'a ekler |
| `disable-account` | İlgili kullanıcı hesabını kilitler |
| `route-null` / `win_route-null` | IP'yi null route'a atar |

## Kanıt  canlı doğrulama (tam stateful döngü)

**Saldırı:** Kali'den `hydra -l fakeuser -P pw.txt ssh://192.168.1.95` (12 başarısız deneme).

**1) Blok (add):**
```
2026/10/18 16:57:35  firewall-drop  command:"add"   192.168.1.105
  tetikleyen: rule 5712 "sshd: brute force... Non existent user" (level 10, T1110)
  kanıt: "Invalid user fakeuser from 192.168.1.105" x8+  (journald)

iptables INPUT:
  1  DROP  0 -- 192.168.1.105  0.0.0.0/0      ← Kali ağ seviyesinde kesildi
```

**2) Otomatik geri açılma (delete)  180 sn sonra:**
```
2026/10/18 17:00:36  firewall-drop  command:"delete"  192.168.1.105   (≈181 sn sonra)

iptables INPUT: (tertemiz blok otomatik kalktı)
```

Saldırgan, brute-force'un **tam ortasında** kesildi ve ceza **kendiliğinden** sona erdi. Beyaz
liste `check_keys` ile sorgulandı  Kali listede olmadığı için bloklandı (yönetim IP'si `.108`
olsaydı atlanırdı).

## ⚠️ Active Response'un tehlikeleri ve güvenli tasarım

Otomatik tepki **iki ucu keskin bıçaktır**; yanlış kurulursa savunma, saldırı aracına döner:

| Risk | Açıklama |
|------|----------|
| **Self-DoS** | Kural FP verirse AR **meşru** kullanıcıyı/sunucuyu bloklar (ör. birkaç yanlış parolayla tüm departman kilitlenir) |
| **Spoofing ile manipülasyon** | Saldırgan kaynak IP'yi bir iş ortağı/iç sunucu gibi gösterip sahte brute-force üretir → AR o **meşru** IP'yi bloklar → kuruma kendi altyapısını DoS'latır |
| **Geri dönülmez eylem** | "hesabı sil" gibi AR, FP'de felaket olur |

**Bu labda uyguladığım güvenli tasarım ilkeleri:**
- **Dar/yüksek güvenli tetikleyici:** tek başarısız giriş değil, **agregeli brute-force** (5712, level 10).
- **Stateful timeout:** kalıcı değil, **geçici** blok (180 sn) → FP kendini toparlar.
- **Beyaz liste:** yönetim istasyonu (`192.168.1.108`) asla bloklanmaz (Aşama 7 FP-tuning mantığı).
- **Kanıtla doğrulama:** `add`/`delete` döngüsü `active-responses.log` + iptables ile teyit edildi.

> Altın kural: **"Bir AR'ın yanlış pozitifi, en kötü saldırıdan daha pahalıya mal olabilir."**
> Otomasyon ne kadar agresifse, tetikleyen kural o kadar kesin olmalı.

## Active Response → SOAR köprüsü

AR = **basit, kural-tabanlı SOAR.** Gerçek **SOAR** (Security Orchestration, Automation and
Response TheHive, Cortex, Shuffle), bunun büyüğüdür: çok adımlı **playbook** otomasyonu
(IOC zenginleştir → vaka aç → analiste ata → onay al → blokla), birçok aracı **orkestra şefi**
gibi bağlar. Bu labdaki `firewall-drop`, bir SOAR playbook'undaki tek bir "Response" adımının
SIEM içindeki hafif versiyonudur.

## İş akışı (nasıl kurdum)

1. **Keşif:** mevcut `<command>`/`<active-response>` bloklarını, beyaz listeyi, kural 5712'yi, sshd
   journald kaynağını, iptables durumunu okudum  AR altyapısının **hazır** olduğunu gördüm.
2. **Tune:** timeout 600→180 (yedek + hedefli edit + restart + daemon sayımı + geri-alma).
3. **Saldırı:** Kali'den SSH brute-force (`hydra`, invalid user, 12 deneme).
4. **Doğrulama:** `add` (Kali DROP) → 180 sn → `delete` (otomatik kalkma); iptables + log ile teyit.

## MITRE ATT&CK
| Teknik | Taktik | Tepki |
|--------|--------|-------|
| **T1110** Brute Force | Credential Access | rule 5712 → `firewall-drop` (otomatik, timeout'lu) |

## Beceriler (bu aşamada kanıtlanan)
`Active Response` · `SOAR temeli` · `Wazuh firewall-drop` · `iptables otomasyonu` ·
`Stateful timeout tepkisi` · `Beyaz liste / self-DoS önleme` · `Brute-force müdahalesi` ·
`Tespit → Müdahale köprüsü`
