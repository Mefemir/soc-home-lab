# Aşama 20 — Threat Hunting + Sigma

> ✅ Tamamlandı Hipotez-güdümlü bir **tehdit avı** (threat hunting) yürüttüm: önce bugünkü
> pencereyi taradım (**temiz → kapsama doğrulandı**), sonra zaman penceresini genişlettim ve
> Temmuz–Ekim verisinde iki sonuç çıktı: (1) Mimikatz izi **zaten yakalanıyordu** (kural 100310),
> (2) **bir tespit boşluğu buldum**  saldırganın SIEM ajanını `net stop Wazuh` ile durdurma
> denemesi yalnızca düşük-seviyeli hazır kuralla görülüyordu. Av döngüsünü **yeni bir kurala**
> dönüştürdüm: **100910 (T1562.001, lvl 12)** yazıp **canlı tetikledim**. Ayrıca özel kurallarımı
> **vendor-bağımsız Sigma** formatına çevirdim (`sigma/*.yml`).

Bu aşama, projemin finali: **tepkisel tespiti** (önceki tüm aşamalar) **proaktif avlanma** ile
tamamlıyorum ve kurallarımı tek bir SIEM'e bağımlı olmaktan kurtarıyorum.

---

## BÖLÜM 1  Threat Hunting (Tehdit Avı)

### Nedir?

Şimdiye kadar hep **alarm bekledim**: bir kural tetiklenir, ben bakarım. Ama en iyi saldırganlar
alarm tetiklemiyor. Threat Hunting bu boşluğu kapatıyor: temel felsefesi **"assume breach"** (ihlal
olduğunu varsay) *"Alarmım yok ama ya zaten içerideyse? Gidip **proaktif olarak arayayım.**"*

| Tepkisel (reactive) | Proaktif (hunt) |
|---------------------|-----------------|
| Kural tetiklenmesini bekler | **Hipotezle** aktif arar |
| Bilinen kötülüğü yakalar | **Bilinmeyeni / kaçanı** arar |

> Aşama 19 (zafiyet) ile akraba buluyorum ikisi de proaktif. Aşama 19 **"açık kapı var mı?"**
> (zayıflık) der; Threat Hunting **"içeri giren oldu mu, benim kuralsız kaldığım yerden?"** (aktif
> tehdit) der.

### Av döngüsü

```
1. HİPOTEZ  → "Saldırgan encoded PowerShell / LOLBin kullanmış olabilir mi?"
2. VERİ     → Wazuh indexer'da elle sorgu (Sysmon/komut satırı)
3. ANALİZ   → normal mi, anormal mi? (gözle incele)
4. BULGU    → ya tehdit (IR'a devret) ya da boşluk/doğrulama
5. YENİ KURAL → avı otomatikleştir (en kalıcı çıktı)
```

### 1. Keşif "neyin içinde avlanacağım?" (ölç, tahmin etme)

Avlanmadan önce veri haritasını çıkardım (`indexer /_cat/indices` + agregasyon):

- **59.015 alert kaydı**, bunların **18.852'si komut satırı (`commandLine`) içeriyor** → encoded/LOLBin avı mümkün.
- Süreç oluşturma bol: **EventID 4688** (18.162) + **Sysmon Event 1** (714).
- İlk göze çarpanlar: `net.exe`/`net1.exe` (144), `schtasks.exe`, `reg.exe`, ve **`mimikatz.exe` komut satırıyla 4 kez**.

> İlkem: boşa sorgu çekip "sonuç yok" görünce *"temiz mi, yoksa veri mi yok?"* ikilemine düşmemek
> için önce verinin **gerçekten orada** olduğunu ve **hangi alan adıyla** durduğunu ölçtüm (Aşama
> 17'de `file` alanını ölçtüğüm gibi).

### 2. Av A PowerShell kötüye kullanım + LOLBin (bugünkü pencere)

Son 1500 komut satırı olayını 3 hipotez altında taradım (encoded PS / domain keşif / araç adı):

```
AV A - PowerShell kötüye kullanım : (temiz)
AV B - Domain keşif LOLBin'leri    : (temiz)
AV C - Bilinen saldırı aracı adı   : (temiz)
En sık komutlar: ngen.exe, conhost.exe, wmiprvse.exe ... (normal OS gürültüsü)
```

**Sonuç: temiz.** Bunu bir başarısızlık olarak görmüyorum  *"bugünkü pencerede şüpheli komut
satırı izi yok; kapsama doğrulandı"* raporlanabilir, değerli bir çıktı.

### 3. Av B  zaman penceresini genişlet (ipucunun peşine düş)

Keşif tüm zamanlarda `mimikatz.exe`'yi göstermişti → iz bugünde değil, **saldırı yaptığım eski
pencerede.** Gerçek avcı burada pencereyi genişletir. Tüm indeksleri (Temmuz–Ekim) taradım:

**Av B-1  kimlik bilgisi / encoded TTP:**
```
[2026-10-09 13:39] (LABPC1)  mimikatz.exe privilege::debug sekurlsa::logonpasswords exit
   → kural 100310 (lvl 12) ZATEN yakalamış  ✅  (tespit DOĞRULANDI)
```

**Av B-2  `net.exe` keşif/LOLBin (196 olay):** içinde iki tür iz:
```
net use \\192.168.1.75\IPC$ /user:LAB\ahmet YanlisParola1..5   (SMB parola deneme  Aşama 7 izi)
net.exe stop Wazuh  /  net start Wazuh                          (!!! güvenlik ajanını durdurma)
```

**Kritik bulgu:** `net stop Wazuh` = **saldırganın SIEM ajanını susturma denemesi (Defense Evasion,
T1562.001).** Ana README coverage tablosunda bu teknik zaten *"bilinen boşluk  kuralsız"* diye
not düşülmüştü. **Av, tam da o boşluğun istismar edildiğine dair kanıt buldu** ve onu yakalayan
tek şey düşük-seviyeli hazır kural (92036, lvl 3) idi. Yüksek-öncelikli özel alarmım yoktu.

---

## BÖLÜM 2  Avın kapanışı: yeni kural 100910 (T1562.001)

Avın en değerli çıktısı: boşluğu **yeni bir kurala** çevirmek. Bir daha elle aramak yerine,
"güvenlik servisini durdurma" artık otomatik **yüksek-seviye** alarm veriyor.

```xml
<group name="sysmon,attack,defense_evasion,">
  <rule id="100910" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)\b(net1?|sc|powershell|stop-service|wmic)\b.*?\bstop\b.*?\b(wazuh|ossec|windefend|sense|sysmon|securityhealthservice|eventlog)</field>
    <description>Defense Evasion: guvenlik/izleme servisini durdurma denemesi (net stop) - $(win.eventdata.commandLine)</description>
    <mitre><id>T1562.001</id></mitre>
    <group>attack,defense_evasion,pci_dss_10.6.1,gdpr_IV_35.7.d,</group>
  </rule>
</group>
```

**Kuralı parça parça:**

| Parça | Anlamı |
|-------|--------|
| `id="100910" level="12"` | Özel kural, yüksek seviye (ajan susturma kritiktir) |
| `<if_group>sysmon_event1</if_group>` | Sadece Sysmon süreç oluşturma olaylarında denensin (net.exe bu ağaca girer  kanıt: hazır 92031/92037 aynı grupta) |
| `\b(net1?\|sc\|powershell\|stop-service\|wmic)\b` | Servis durdurabilen araçlar (`net`, `net1`, `sc`, PowerShell `Stop-Service`, `wmic`) |
| `.*?\bstop\b` | "stop" fiili (`net **stop**`, `Stop-Service`) |
| `.*?\b(wazuh\|ossec\|windefend\|sense\|sysmon\|...)` | Hedef **güvenlik/izleme** servisleri  **önek** eşleşmesi (sondaki `\b` yok → `WazuhSvc`, `Sysmon64` de yakalanır) |
| `<mitre>T1562.001</mitre>` | Impair Defenses: Disable or Modify Tools |

> **Yaşadığım hata ve ders (ölç, tahmin etme):** İlk sürümde regex'in sonunda `\b` vardı.
> Deterministik öz-testim (`net stop WazuhTestFake` → beklenen `True`, bulunan `False`) bunu
> yakaladı: `WazuhTestFake`'te "Wazuh" bitişik olduğu için sondaki kelime sınırı eşleşmiyordu.
> Gerçek servis adları ekli olduğundan (`WazuhSvc`), sondaki `\b`'yi kaldırıp **önek eşleşmesine**
> geçtim. Canlıya çıkmadan önce öz-test kuralın mantığını doğruladı.

**Canlı doğrulama (zararsız):** LABPC1'de `net stop WazuhTestFake` çalıştırdım  **var olmayan**
servis ("Hizmet adı geçersiz"), ajan çalışmaya devam etti, ama süreç oluşturma olayı loglandı:

```
[2026-10-19 12:57:34] (LABPC1)  net   stop WazuhTestFake  → 100910 (lvl 12, T1562.001) ✅
[2026-10-19 12:57:34] (LABPC1)  net1  stop WazuhTestFake  → 100910 (lvl 12, T1562.001) ✅
```

> `net` dahili olarak `net1`'i çağırdığı için iki olay da düştü. **Av → kural → canlı kanıt** turu
> kapandı. (Gerçek `Wazuh` servisini bilerek durdurmadım  ajan kapanmasın; sahte isim aynı
> telemetriyi güvenle üretiyor.)

---

## BÖLÜM 3  Sigma (vendor-bağımsız kural formatı)

### Problem ve çözüm

Kurallarımı **Wazuh XML**'iyle yazdım; ama Splunk **SPL**, Elastic/Sentinel **KQL**, QRadar **AQL**
konuşuyor. Aynı tespiti her platforma ayrı yazmak = vendor lock-in. **Sigma**, tespiti **tek jenerik
YAML**'da yazmamı sağlıyor; bir dönüştürücü (`sigma-cli`) onu istediğim SIEM diline çeviriyor.

```
            ┌─► Splunk SPL
Sigma YAML ─┼─► Elastic / Sentinel KQL
(bir kez    ├─► QRadar AQL
 yaz)       └─► Wazuh / ...
```
> SIEM tespitleri için Sigma = antivirüs imzaları için YARA / **evrensel priz adaptörü**.

### Bu repoda çevirdiğim kurallar (`sigma/`)

| Sigma dosyası | Karşılığı (Wazuh) | MITRE |
|---------------|-------------------|-------|
| [`security_service_stop.yml`](sigma/security_service_stop.yml) | **100910** (bu avdan doğdu) | T1562.001 |
| [`suspicious_process_outbound_c2.yml`](sigma/suspicious_process_outbound_c2.yml) | 100600 (C2) | T1071 |
| [`dns_tunneling_long_subdomain.yml`](sigma/dns_tunneling_long_subdomain.yml) | 100702 (DNS exfil) | T1048 |

### Sigma kuralının yapısı

```yaml
logsource:                      # hangi log kaynağı
  category: process_creation
  product: windows
detection:
  selection_tool:               # eşleşme koşulları (alan + değer)
    Image|endswith: ['\net.exe', '\sc.exe', ...]
  selection_action:
    CommandLine|contains: 'stop'
  selection_service:
    CommandLine|contains: ['wazuh', 'sysmon', ...]
  condition: all of selection_* # mantık
level: high
tags: [attack.defense_evasion, attack.t1562.001]   # MITRE eşlemesi
```

| Alan | Görevi |
|------|--------|
| `logsource` | Log kaynağı (windows / process_creation) |
| `detection.selection_*` | Eşleşme blokları (alan + değer) |
| `condition` | Mantık (`all of selection_*`) |
| `level` + `tags` | Ciddiyet + MITRE ATT&CK |

### Dönüştürme (hedef SIEM diline)

`sigma-cli` ile aynı YAML'ı farklı SIEM'lere çeviriyorum:

```bash
pip install sigma-cli pysigma-backend-splunk pysigma-backend-elasticsearch

# Splunk SPL üret
sigma convert -t splunk  sigma/security_service_stop.yml
# Elastic (Lucene/DSL) üret
sigma convert -t lucene  sigma/security_service_stop.yml
```

Örn. `security_service_stop.yml` → Splunk'ta kabaca:
```spl
Image IN ("*\\net.exe","*\\sc.exe",...) CommandLine="*stop*"
  CommandLine IN ("*wazuh*","*sysmon*",...)
```
Yani **bir kez yaz → her SIEM'e çevir.** Yarın Splunk'lı bir ekibe geçsem kurallarım benimle gelir;
SigmaHQ'daki binlerce topluluk kuralını da kendi ürünüme çevirip kullanabilirim.

---

## İş akışı (nasıl yaptım)

1. **Keşif:** indexer'daki indeksler + Sysmon/komut satırı dağılımını ölçtüm (avın haritası).
2. **Av A:** bugünkü pencereyi 3 hipotezle taradım → temiz (kapsama doğrulandı).
3. **Av B:** pencereyi genişlettim → Mimikatz zaten yakalanıyor (100310) + `net stop Wazuh` **boşluğunu** buldum.
4. **Kural:** 100910 (T1562.001) yazdım; `wazuh-analysisd -t` + regex öz-test + daemon kontrolü (geri-almalı).
5. **Canlı kanıt:** LABPC1 `net stop WazuhTestFake` → 100910 lvl 12 tetiklendi (12:57:34, ×2).
6. **Sigma:** 3 özel kuralı vendor-bağımsız YAML'a çevirdim (`sigma/`), YAML'ı doğruladım.

## MITRE ATT&CK
- **T1562.001** Impair Defenses: Disable or Modify Tools (yeni kural 100910)
- Avda doğruladığım: **T1003.001** (Mimikatz, 100310), **T1110/T1021.002** (SMB parola deneme)

## Beceriler (bu aşamada kanıtlanan)
`Threat Hunting` · `Hipotez-güdümlü avlanma` · `assume breach` · `Wazuh indexer sorgulama (DQL/REST)` ·
`Detection gap bulma` · `Av → kural dönüşümü` · `T1562.001 Defense Evasion tespiti` ·
`Sigma` · `Vendor-bağımsız detection engineering` · `sigma-cli dönüşümü` · `pcre2 regex öz-testi`
