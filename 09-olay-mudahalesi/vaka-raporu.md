# Vaka Raporu — Çok Aşamalı Active Directory Saldırısı

> **Olay No:** IR-2026-001
> **Rapor tarihi:** 2026-10-10
> **Analist:** melih (SOC / Mavi Takım)
> **Ortam:** Ev SOC Lab — lab.local domaini (DC01, LABPC1), Wazuh SIEM (wazuh-siem)
> **Sınıflandırma:** İç lab tatbikatı — kontrollü, yetkili saldırı simülasyonu

---

## 1. Yönetici Özeti

Kontrollü lab ortamında, bir saldırganın (Kali Linux) bir Active Directory alanına karşı
**baştan sona çok aşamalı bir saldırı zinciri** yürüttüğü senaryo simüle edildi ve tüm
aşamalar SIEM (Wazuh) üzerinden **tespit edildi.**

Saldırı zinciri:

```
İlk erişim denemesi        Kimlik ele geçirme         Ağda yayılma
──────────────────         ──────────────────         ────────────
Brute Force (T1110)  →  Kerberoasting (T1558.003)  →  Credential Dumping (T1003.001)  →  Lateral Movement (PsExec, T1021.002)
```

Zincirin **her adımı** ya özel yazılan kurallarla (100100, 100300, 100310, 100320) ya da
Wazuh'un hazır ruleset'iyle (92650 vb.) yakalandı. Gerçek bir ortamda bu zincir, bir
Domain Admin hesabının tam olarak ele geçirilmesiyle (domain compromise) sonuçlanabilirdi.

**Sonuç:** Tespit kapsamı saldırının her evresinde çalıştı. Kök neden: zayıf servis
hesabı parolası + korumasız LSASS + kısıtlanmamış admin paylaşımları.

---

## 2. Olay Zaman Çizelgesi (Timeline)

> Zaman çizelgesi, farklı aşamalardaki temsili olayların mantıksal sırasıdır.

| # | Evre | Kaynak | Hedef | Tespit (rule.id) | Log kanıtı |
|---|------|--------|-------|------------------|------------|
| 1 | **Brute Force** | Kali | DC01 / kullanıcı hesapları | 100100 (lvl 10) | Çok sayıda 4625 (başarısız oturum açma) |
| 2 | **Kerberoasting** | Kali | svc-sql (SPN'li servis hesabı) | 100300 (lvl 12) | 4769 + ticketEncryptionType 0x17 (RC4) |
| 3 | **Credential Dumping** | LABPC1 (yerel) | LSASS belleği | 100310 + 100320 (lvl 12-13) | Sysmon Event 1 (Mimikatz) + Event 10 (LSASS erişimi, GrantedAccess 0x1010) |
| 4 | **Lateral Movement** | Kali (çalınan admin) | DC01 | 92650 (lvl 12) + 92218 + 92652 | 4624 Type 3 + 7045 (yeni servis) + ADMIN$ yazımı |

**Patient zero (hasta sıfır):** İlk tavize noktası, zayıf parolası brute-force ile elde
edilebilen/Kerberoasting ile kırılabilen **svc-sql servis hesabıdır.** Saldırgan bu
kimliği kaldıraç olarak kullanıp LABPC1 üzerinde kimlik dökümü yapmış ve oradan DC'ye
yatay geçmiştir.

---

## 3. Tespit ve Analiz

### 3.1 Evre 1 — Brute Force (T1110)
- **Ne görüldü:** Kısa sürede çok sayıda başarısız oturum açma (Event 4625).
- **Kural:** Özel kural 100100 — eşik tabanlı başarısızlık seli tespiti.
- **Analiz:** Tek IP'den yoğun deneme = otomatik parola saldırısı imzası.

### 3.2 Evre 2 — Kerberoasting (T1558.003)
- **Ne görüldü:** svc-sql hesabı için **RC4 (0x17)** şifreli TGS bileti isteği (Event 4769),
  kaynak Kali IP.
- **Kural:** Özel kural 100300. Araçtan bağımsız (teknik tespiti) — GetUserSPNs, Rubeus
  ya da manuel fark etmez.
- **Analiz:** RC4 bileti talebi, saldırganın bileti offline kırıp (hashcat 13100) servis
  hesabı parolasını ele geçirme niyetini gösterir. Modern ortamda AES (0x12) beklenir;
  RC4 talebi başlı başına şüphelidir (downgrade).

### 3.3 Evre 3 — Credential Dumping (T1003.001)
- **Ne görüldü:** LABPC1'de Mimikatz çalıştırıldı; LSASS belleğine okuma erişimi
  (GrantedAccess 0x1010).
- **Kurallar:** 100310 (araç imzası — commandLine) + 100320 (davranış — LSASS erişimi).
- **Analiz:** Dump aracı sürüm uyumsuzluğundan (Key import) başarısız olsa bile **LSASS'a
  erişim gerçekleşti.** Başarısız saldırı da gerçek bir olaydır — tespit tetiklendi.
- **Ayrıca:** Defender kapatma girişimi (T1562.001) — Defense Evasion sinyali.

### 3.4 Evre 4 — Lateral Movement / PsExec (T1021.002)
- **Ne görüldü:** Çalınan admin kimliğiyle DC'ye uzaktan: ADMIN$ paylaşımına binary
  yükleme → yeni servis (7045) → uzaktan NTLM oturum (4624 Type 3).
- **Kurallar:** Hazır ruleset — 92650 (PsExec imzası), 92218 (admin paylaşımı), 92652
  (olası Pass-the-Hash). Özel kural gerekmedi.
- **Analiz:** Kill-chain'in son halkası — saldırgan artık DC üzerinde kod çalıştırabiliyor.
  Bir domain compromise'in eşiği.

---

## 4. Kapsama (Containment) — yapılması gerekenler

Gerçek bir olayda, yukarıdaki zincir doğrulandığı an:

1. **LABPC1'i ağdan izole et** (kimlik dökümünün yapıldığı makine — en kirli nokta).
2. **svc-sql ve ele geçirilen admin hesabını kilitle/devre dışı bırak.**
3. **DC01'de oluşturulan şüpheli servisi durdur** (PsExec servis binary'si).
4. Saldırganın kaynak IP'sini (Kali) firewall'da **blokla.**

> İlke: *Containment önce, analiz sonra devam eder.* Kanamayı durdur, ama kanıtı
> (bellek, loglar, disk görüntüsü) bozmadan.

---

## 5. Temizleme (Eradication) ve Kurtarma (Recovery)

**Eradication:**
- PsExec servisini ve bıraktığı binary'yi DC'den kaldır.
- Mimikatz ve ilgili araçları LABPC1'den sök.
- **Ele geçirilen tüm kimlikleri sıfırla:** svc-sql, ilgili admin, ve LABPC1'de oturum
  açmış tüm hesaplar (LSASS'ta hash'leri durmuş olabilir) — **krbtgt dahil** iki kez
  parola sıfırlaması (Golden Ticket riskine karşı) değerlendirilmeli.

**Recovery:**
- İzole makineleri temiz/yeniden kurulmuş halde ağa döndür.
- Sıfırlanan hesaplarla normal operasyona dön.
- İlk 48 saat **yoğun izleme** (aynı IOC'ler tekrar görünüyor mu).

---

## 6. IOC'ler (Indicators of Compromise)

| Tür | Gösterge |
|-----|----------|
| Hesap | svc-sql (hedef), ele geçirilen Administrator |
| Teknik imza | 4769 + RC4 (0x17); Sysmon Event 10 LSASS GrantedAccess 0x1010 |
| Süreç | mimikatz.exe (IMPHASH 55EE500BB4BDFC49F27A98AE456D8EDF) |
| Davranış | ADMIN$ paylaşımına binary + yeni servis (7045) + 4624 Type 3 NTLM |
| Kaynak | Kali saldırgan IP'si |

---

## 7. MITRE ATT&CK Eşlemesi

| Evre | Teknik | Taktik |
|------|--------|--------|
| 1 | T1110 — Brute Force | Credential Access |
| 2 | T1558.003 — Kerberoasting | Credential Access |
| 3 | T1003.001 — LSASS Memory | Credential Access |
| 3 | T1562.001 — Impair Defenses | Defense Evasion |
| 4 | T1021.002 — SMB/Admin Shares | Lateral Movement |
| 4 | T1570 — Lateral Tool Transfer | Lateral Movement |
| 4 | T1569.002 — Service Execution | Execution |
| 4 | T1550.002 — Pass-the-Hash (ilişkili) | Lateral Movement |

(Bkz. Aşama 8 — Navigator kapsam haritası.)

---

## 8. Dersler ve Öneriler (Lessons Learned)

### Kök neden
Zayıf **servis hesabı parolası** (Kerberoasting ile kırılabilir) + **korumasız LSASS**
(credential dumping) + **kısıtlanmamış admin paylaşımları** (lateral movement).

### Somut öneriler
| Alan | Öneri | Hangi evreyi kırar |
|------|-------|--------------------|
| Servis hesapları | **gMSA** (otomatik uzun parola) veya 25+ karakter parola; RC4 devre dışı, AES zorla | Kerberoasting |
| LSASS | **Credential Guard + LSA Protection (RunAsPPL)** | Credential Dumping |
| Admin hesapları | **LAPS** (makine başına benzersiz local admin); DA'lar workstation'a girmesin | Lateral Movement |
| Ağ/kimlik | NTLM'i kısıtla (Kerberos'a zorla); SMB imzalama; segmentasyon | PtH / Lateral |
| Parola politikası | Kilitleme eşiği + güçlü politika | Brute Force |
| Tespit boşluğu | T1562.001 (Defender kapatma) için **özel kural** ekle | Defense Evasion |

### Tespit tarafı dersi
Zincirin her halkası yakalandı. **Davranışsal kurallar (100300, 100320)** araçtan
bağımsız olduğu için en dayanıklı katmanı oluşturdu; imza kuralları (100310) adli
zenginlik kattı; hazır ruleset gürültülü teknikleri (PsExec) zaten kapsadı. Olgun
yaklaşım: davranışla geniş ağ at, imzayla zenginleştir, boşlukları özel kuralla kapat.

---

## 9. Ekran görüntüleri

> `gorseller/` klasörüne eklenecek:
- `gorseller/09-timeline.png` — Wazuh'ta zincirin uçtan uca alarm akışı
- `gorseller/09-navigator.png` — saldırının ATT&CK haritası (Aşama 8 layer'ı)
