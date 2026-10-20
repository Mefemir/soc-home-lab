# Aşama 11 — Alarm Triyajı ve Playbook'lar

> ✅ Tamamlandı  önceki aşamalarda **yazdığım** tespit kurallarını (100100, 100300,
> 100320) bu aşamada **analist gözüyle** ele aldım: bir alarm çaldığında onu nasıl
> değerlendiriyorum, gerçekle gürültüyü nasıl ayırıyorum, ne zaman eskale ediyorum.
> Her kural için tekrarlanabilir bir **triyaj playbook'u** yazdım.

## Triyaj (alert triage) nedir?

Bir SIEM günde **binlerce** alarm üretir; analist hepsini derinlemesine inceleyemez.
**Triyaj**, gelen her alarma hızlı bir ilk bakış atıp şu kararı vermektir:

> "Bu gerçek bir tehdit mi, yoksa gürültü mü? Ne kadar acil? Şimdi ne yapmalıyım?"

Bir **SOC L1 analistinin işinin %70-80'i budur.** Kural yazmak (detection engineering)
kadar, o kural çaldığında **doğru yorumlamak** da işin özüdür. Bu aşama, lab'daki tüm
mevcut tespitleri "tespit mühendisi" koltuğundan "nöbetçi analist" koltuğuna taşır.

## En kritik kavram: TP / FP / BTP / FN

Her alarm dört kutudan birine girer. Ayıran **tek soru** şudur:
**"Alarmın tarif ettiği aktivite gerçekten oldu mu?"**

| Terim | Açılım | Aktivite oldu mu? | Kötücül mü? | Çözüm |
|-------|--------|-------------------|-------------|-------|
| **TP** | True Positive | ✅ Oldu | ✅ Evet | **Müdahale** (contain / eskale) |
| **BTP** | Benign True Positive | ✅ Oldu | ❌ Hayır (yetkili/meşru) | **İstisna ekle** (beyaz liste) |
| **FP** | False Positive | ❌ **Olmadı** (kural yanıldı) | ❌ Hayır | **Kuralı düzelt** (tuning) |
| **FN** | False Negative | ✅ Oldu | ✅ Evet ama **alarm çalmadı** | **Yeni kural** (gap kapatma) |

> **FP ile BTP'yi karıştırma  en sık yapılan hata.** İkisinde de "zarar yok"; fark,
> aktivitenin **gerçekleşip gerçekleşmediğidir**. Lab'dan örnekler:
> - Aşama 5'te `explorer.exe` "şüpheli" diye çaldı ama ortada şüpheli süreç *yoktu*
>   (imza geçerli, hash iyi) → aktivite olmadı → **FP** → *bastırma kuralı 100200*.
> - Aşama 7'de Defender'ın `MsMpEng.exe`'si LSASS'a *gerçekten* eriştiği için 100320
>   çaldı → aktivite **oldu** ama meşru → **BTP** → *istisna/beyaz liste*.
>
> **FN en tehlikelisidir:** onu göremezsin, çünkü hiç alarm çalmaz. SOC'un olgunluğu
> FN'leri azaltmakla ölçülür  Aşama 8'deki Navigator gap analizi tam da bunun içindir.

> **Alert fatigue (alarm körlüğü):** FP'ler çoğalırsa analist "nasılsa yine yanlış" deyip
> ciddiye almaz ve bir gün *gerçek* olanı kaçırır. Bu yüzden FP tuning bir temizlik değil,
> doğrudan bir **güvenlik meselesidir.**

## Triyaj döngüsü (analistin kafasındaki checklist)

Bir alarm geldiğinde sırayla 5 soru:

1. **Ne çaldı?** → `rule.id`, `rule.level`, MITRE tekniği. (örn. 100300 / lvl 12 / T1558.003)
2. **Nerede / kimde?** → `agent.name`, kullanıcı, kaynak IP. (DC01 mi, sıradan workstation mı?)
3. **Gerçek mi? (TP/FP/BTP)** → ilgili log alanlarına bak. **İşin kalbi bu adımdır.**
4. **Etki / kapsam?** → tek makine mi, yayılıyor mu? Kill-chain'in neresi?
5. **Sırada ne var?** → **Kapat (FP/BTP)** · **Eskale et (L2)** · **Müdahale et (contain)**  ve her durumda **dokümante et.**

## Önceliklendirme  her TP eşit değildir

İki eksende düşün:

- **Varlık kritikliği:** Domain Controller > sunucu > kullanıcı bilgisayarı. (DC düşerse
  tüm domain düşer.)
- **Kill-chain evresi:** Recon < Credential Access < Lateral Movement < Exfiltration.
  Sağa gittikçe daha acil.

`rule.level` (0-15) bir **ön-öncelik** verir (12+ kritik) ama **son söz analistindir**:
DC'de kill-chain'in ortasındaki level 3'lük bir olay, workstation'daki level 10'dan daha
acil olabilir.

## Playbook nedir, neden var?

**Playbook** = belirli bir alarm türü geldiğinde izlenecek, **yazılı ve tekrarlanabilir**
adımlar. Faydası: **tutarlılık** (kim bakarsa baksın aynı sonuç), **hız**, **eğitim**
(yeni analist okuyarak öğrenir) ve **kritik adımın atlanmaması**.

Bir triyaj playbook'unun iskeleti: *Tetikleyici → Önem → Triyaj kontrolleri (somut
sorgular) → TP/FP karar kriteri → Müdahale → Eskalasyon yolu.*

---

# Triyaj Playbook'ları

Aşağıdaki üç playbook, lab'da **gerçekten yazdığım ve tetiklediğim** kurallara aittir.
DQL sorguları Wazuh Dashboard → **Threat Hunting → Discover** ekranında çalışır.

## Playbook PB-01 Brute Force (rule 100100, T1110)

| Alan | Değer |
|------|-------|
| **Tetikleyici** | `rule.id:100100` (120 sn'de 5+ başarısız 4625 bkz. Aşama 5) |
| **Önem** | level 10 orta/yüksek |
| **Taktik** | Credential Access (T1110) |

**1. İlk bakış (sorgu):**
```
rule.id:100100
```
Ardından aynı kaynağı genişlet:
```
data.win.eventdata.ipAddress:"<srcip>" and (rule.id:60122 or rule.id:60106)
```

**2. Triyaj kontrolleri:**
- **Kaynak IP** içeriden mi (`192.168.1.0/24`), dışarıdan mı?
- **Tek hesap mı, çok hesap mı?** Çok hesap + az parola = *password spraying*.
- **Saat:** mesai dışı mı?
- **🔑 En kritik soru:** bu başarısızlık selinden *sonra* aynı kaynaktan bir **4624
  (başarılı giriş)** var mı?
  ```
  data.win.eventdata.ipAddress:"<srcip>" and data.win.system.eventID:"4624"
  ```

**3. TP / FP / BTP kararı:**
| Gözlem | Sonuç | Aksiyon |
|--------|-------|---------|
| Çok deneme **+ ardından 4624 başarılı** | **TP  yüksek** | Hesap ele geçmiş olabilir → **eskale + IP engelle + parola sıfırla** |
| Çok/hızlı deneme, başarı yok | **TP  orta** | IP'yi engelle, izlemeye al |
| Tek kullanıcı, 2-3 deneme, mesai içi | muhtemelen **FP/BTP** (parola unutan kullanıcı) | Dokümante et; tekrar ediyorsa eşiği gözden geçir |

**4. Eskalasyon:** Başarılı giriş (4624) görülürse → derhal **L2'ye eskale**, olay kaydı aç.

## Playbook PB-02  Kerberoasting (rule 100300, T1558.003)

| Alan | Değer |
|------|-------|
| **Tetikleyici** | `rule.id:100300` (4769  RC4/`0x17` servis bileti isteği  bkz. Aşama 6) |
| **Önem** | level 12  yüksek |
| **Taktik** | Credential Access (T1558.003) |

**1. İlk bakış (sorgu):**
```
rule.id:100300
```

**2. Triyaj kontrolleri:**
- **Hedef servis hesabı** (`ServiceName` / `svc-sql` gibi) hangisi? SPN'li hesap mı?
- **Bilet şifreleme tipi** gerçekten `0x17` (RC4) mı? Modern ortam çoğunlukla `0x12`
  (AES) kullanır → `0x17` **şüphe işaretidir** (saldırgan kırması kolay olsun diye RC4 ister).
- **İsteği yapan kaynak** (`Client Address`) normalde bu servise erişen bir makine mi,
  yoksa alakasız bir workstation mı?
- **Hacim:** kısa sürede **çok sayıda farklı SPN** için bilet mi istendi? (toplu
  Kerberoasting = `GetUserSPNs` gibi araç imzası)

**3. TP / FP / BTP kararı:**
| Gözlem | Sonuç | Aksiyon |
|--------|-------|---------|
| Alakasız bir host'tan, kısa sürede çok SPN, 0x17 | **TP  yüksek** | **Eskale** + ilgili servis hesabı parolasını döndür (uzun/karmaşık) |
| Tek servis hesabı, bilinen uygulama sunucusundan, tek istek | olası **BTP** | Normal uygulama davranışı olabilir → doğrula, dokümante et |
| Legacy uygulama RC4 kullanıyor diye sürekli çalıyor | **FP/gürültü** | Bilinen kaynağı istisna et; AES'e geçişi öner |

**4. Eskalasyon:** Çok SPN + alakasız kaynak deseni → **L2'ye eskale**; hesap ele geçirme
sonrası Kerberoasting genelde bir sonraki adıma (lateral movement) hazırlıktır.

## Playbook PB-03  LSASS Credential Dumping (rule 100320, T1003.001)

| Alan | Değer |
|------|-------|
| **Tetikleyici** | `rule.id:100320` (Sysmon Event 10  bir süreç LSASS'a şüpheli erişim  bkz. Aşama 7) |
| **Önem** | level 13  kritik |
| **Taktik** | Credential Access (T1003.001) |

**1. İlk bakış (sorgu):**
```
rule.id:100320 or rule.id:100310
```

**2. Triyaj kontrolleri (🔑 bu alarm FP/BTP'ye en açık olandır):**
- **LSASS'a erişen süreç kim?** (`SourceImage`)
  - Meşru örnekler: `MsMpEng.exe` (Defender), `svchost.exe`, `wininit.exe`, EDR ajanları.
  - Şüpheli örnekler: `mimikatz.exe`, `rundll32.exe`, `procdump.exe`, PowerShell, bilinmeyen/geçici dizinden çalışan exe.
- **GrantedAccess** değeri klasik dump deseni mi? (`0x1010`, `0x1410`, `0x143a` → bellek okuma)
- **Süreç imzalı mı, yolu neresi?** `C:\Windows\...` meşru, `C:\Users\...\Temp\` şüpheli.
- **Ebeveyn süreç** ne? Beklenmedik ebeveyn (örn. Word → PowerShell → LSASS) zincirin kanıtıdır.

**3. TP / FP / BTP kararı:**
| Gözlem | Sonuç | Aksiyon |
|--------|-------|---------|
| İmzasız/geçici dizinden süreç, dump GrantedAccess | **TP  kritik** | **Host'u izole et** + eskale + kimlik bilgisi devri varsay |
| `MsMpEng.exe` (Defender) imzalı, `C:\Program Files\...` | **BTP** | AV'nin meşru taraması → **istisna kuralı yaz** (bkz. aşağıda) |
| Kural LSASS olmayan bir süreci yanlış eşledi | **FP** | Kural mantığını düzelt (tuning) |

> **Neden FP değil BTP?** Defender LSASS'a *gerçekten* erişti; aktivite oldu ama meşrudu.
> Bu yüzden "kuralı boz" değil, "bilinen iyi kaynağı istisna et" çözülür. Örnek bastırma
> kuralı (Aşama 7'de önerilen 100321 mantığı):
> ```xml
> <rule id="100321" level="0">
>   <if_sid>100320</if_sid>
>   <field name="win.eventdata.sourceImage" type="pcre2">(?i)\\MsMpEng\.exe$</field>
>   <description>Benign: Defender (MsMpEng.exe) LSASS erisimi - FP/BTP bastirildi</description>
> </rule>
> ```

**4. Eskalasyon:** Meşru olmayan her LSASS erişimi → **derhal L2 + host izolasyonu**; bu
kill-chain'in en kritik halkalarından biridir (kimlik bilgisi hırsızlığı → lateral movement).

---

## SOC katmanları (ben neredeyim?)

- **L1 (Tier 1):** Triyaj, ilk inceleme, FP eleme, eskalasyon. ← **hedef pozisyonum**
- **L2 (Tier 2):** Derin inceleme, olay müdahalesi, korelasyon.
- **L3 (Tier 3):** Threat hunting, gelişmiş IR, **detection engineering** ← bu lab'da kural
  yazarak zaten bu işi yaptım; bu beni güçlü bir aday yapıyor.

## Teslim ettiklerim

- [x] Triyaj kavramı ve TP/FP/BTP/FN karar modeli
- [x] 5 adımlık triyaj döngüsü + önceliklendirme (varlık kritikliği × kill-chain)
- [x] 3 somut triyaj playbook'u (100100, 100300, 100320)  DQL sorguları + karar tabloları
- [ ] Ekran görüntüleri (`gorseller/`  bir alarmın triyaj akışı eklenebilir)

---
