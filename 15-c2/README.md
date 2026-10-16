# Aşama 15 — Command & Control (C2) Tespiti

> ✅ Tamamlandı — saldırganın ele geçirdiği makineyle dış sunucusu arasındaki gizli
> yönetim kanalı (C2) LABPC1'de zararsız olarak simüle edildi, **Sysmon Event 3 (ağ
> bağlantısı)** ile yakalandı ve iki özel Wazuh kuralıyla doğrulandı: **100600** (şüpheli
> süreç dışarı bağlandı, level 10) ve **100601** (beaconing deseni, level 13). Aşama 8'deki
> MITRE kapsam haritasındaki **Command & Control (TA0011)** boşluğu bu aşamayla kapandı.

## Command & Control (C2) nedir?

Saldırgan bir makineye girdikten (initial access) ve kalıcılık bıraktıktan (Aşama 14)
sonra, makineyi **uzaktan yönetmek** ister: komut göndermek, dosya indirmek, ağda
ilerlemek. Ele geçmiş makine ile saldırganın dış sunucusu arasındaki bu **gizli yönetim
kanalına Command & Control (C2 / C&C)** denir. MITRE ATT&CK'te başlı başına bir taktiktir:
**TA0011**.

C2 kurulmadan saldırgan içeride "sağır-dilsiz"dir. Kanal açıldığı an makine saldırganın
uzaktan kumandasına girer — bu yüzden C2'yi yakalamak = saldırının **beynini** kesmek.

## İki model: reverse shell vs beacon

| Model | Nasıl çalışır | İz |
|-------|---------------|-----|
| **Reverse shell** | Ele geçmiş makine saldırgana bağlanıp hattı **açık tutar** (firewall giden bağlantıya izin verir, geleni engeller — bu asimetri kullanılır) | Tek dış IP'ye uzun, sabit bağlantı; gürültülü |
| **Beacon** (modern C2 standardı: Cobalt Strike, Sliver, Meterpreter) | Makine aralıklarla "emir var mı?" diye **kısa kısa uğrar** (check-in), kapar, bekler, tekrarlar | Periyodik, kısa, tekrar eden bağlantılar = "beaconing" |

Beacon'u gizleyen iki ayar:
- **Sleep:** iki check-in arası süre (örn. 60 sn).
- **Jitter:** sleep'e eklenen rastgelelik (örn. %30) → düzenli deseni insan trafiği gibi
  göstermeye çalışır. Ama *aynı iç makineden aynı dış hedefe tekrar eden bağlantılar*
  istatistiksel olarak yine sırıtar.

## Anahtar terimler ve kanallar

| Öğe | Anlamı |
|-----|--------|
| **Sysmon Event 3** | Network connection — bir sürecin dışarı ağ bağlantısı açması |
| **Beaconing** | Periyodik check-in deseni (C2'nin imzası) |
| **HTTP/HTTPS (443)** | En yaygın C2 kanalı (şifreli → içerik görünmez, **desen/hedef** incelenir) |
| **DNS tunneling** | DNS neredeyse hiç engellenmez (Aşama 17'de ele alınacak) |

## Tespit mantığı — "kim bağlandı?"

C2'nin ana kanıtı Sysmon **Event 3**'tür. Bakılan alanlar: `image` (hangi süreç),
`destinationIp` / `destinationPort` (nereye), `initiated` (giden mi).

1. **Şüpheli süreç dışarı mı çıkıyor?** `powershell.exe`, `cmd.exe`, `rundll32.exe`,
   `mshta.exe`, `wscript.exe`… normalde internete bağlanmaz. Çıkarsa C2 şüphesi.
2. **Beaconing deseni:** aynı şüpheli süreçten kısa sürede **tekrar eden** bağlantılar →
   frekans korelasyonu (05'teki brute-force eşiğinin ağ versiyonu).
3. **Alışılmadık hedef/port:** bilinen iş hedeflerinin dışına garip portlar.

> **FP/BTP uyarısı:** C2 tespiti yanlış pozitife **en yatkın** alanlardan biridir, çünkü
> *her uygulama ağ bağlantısı açar* (tarayıcı, OneDrive, Teams…). Bu yüzden kural "bağlantı
> var" demez; **"beklenmedik bir süreç dışarı bağlandı"** veya **"desen beacon gibi"** der.
> Meşru PowerShell yönetim scriptleri BTP olabilir → bağlamla (hedef, saat, kaynak) ayrılır.

## Ne yaptık (adımlar)

1. **Keşif:** LABPC1'de Sysmon'un Event 3 ürettiğini doğruladık (SwiftOnSecurity config'i
   seçili süreçler için ağ bağlantısını loglar — powershell dahil).
2. **Saldırı simülasyonu (LABPC1 → Kali `192.168.1.105`):** PowerShell ile tekrar eden
   kısa TCP bağlantıları (zararsız beacon taklidi — gerçek C2 aracı değil).
3. **İki katmanlı özel kural** yazıp güvenli deploy ettik (yedek → `wazuh-analysisd -t` →
   hata olursa otomatik geri alma → restart).
4. **Doğrulama:** 100600 (level 10) ve 100601 beaconing (level 13) gerçek olaylarla düştü.

### Özel tespit kuralları (iki katmanlı tasarım)
> Kuralların nasıl yazıldığını adım adım anlatan genel rehber için →
> [Aşama 05 — Wazuh kuralı nasıl yazılır?](../05-brute-force/#wazuh-kuralı-nasıl-yazılır-bu-repodaki-ilk-kural-burada)

`/var/ossec/etc/rules/local_rules.xml`:
```xml
<group name="sysmon,c2,attack,">

  <!-- 100600: Supheli surec disari ag baglantisi acti - TABAN (T1071) -->
  <rule id="100600" level="10">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID">^3$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\+(powershell|powershell_ise|cmd|rundll32|mshta|wscript|cscript|regsvr32|certutil|bitsadmin)\.exe$</field>
    <description>C2 suphesi: supheli surec disari ag baglantisi acti - $(win.eventdata.image) -> $(win.eventdata.destinationIp):$(win.eventdata.destinationPort) (T1071)</description>
    <mitre><id>T1071</id></mitre>
    <group>c2,network,</group>
  </rule>

  <!-- 100601: Beaconing - 120sn icinde 5+ kez = C2 check-in deseni -->
  <rule id="100601" level="13" frequency="5" timeframe="120">
    <if_matched_sid>100600</if_matched_sid>
    <description>C2 beaconing suphesi: supheli surec 120sn icinde 5+ kez disari baglandi (periyodik check-in deseni) (T1071)</description>
    <mitre><id>T1071</id></mitre>
    <group>c2,beaconing,</group>
  </rule>

</group>
```

### Kuralı parça parça
| Satır | Ne yapar |
|-------|----------|
| `<rule id="100600" level="10">` | **Taban** kural: şüpheli süreç dışarı bağlandı |
| `<if_group>sysmon</if_group>` + `<field ...eventID>^3$</field>` | Sysmon **Event 3** (ağ bağlantısı) |
| `<field name="win.eventdata.image" type="pcre2">(?i)\\+(powershell\|cmd\|rundll32\|...)\.exe$</field>` | Bağlanan süreç **şüpheli bir ikili** mi? `\\+` = bir/daha fazla ters bölü (eventchannel çiftler!), `(a\|b)` = alternatifler, `\.exe$` = yol bu ikiliyle bitiyor |
| `<rule id="100601" ... frequency="5" timeframe="120">` | **Beaconing** korelasyonu: 120 sn'de 5+ |
| `<if_matched_sid>100600</if_matched_sid>` | 100600 bu eşiği aşarsa tek bir üst-seviye alarm üretir (05'teki 100100 ile aynı mantık) |

## Doğrulama (gerçek kanıt)

```
100600 → level 10 · LABPC1 · powershell.exe -> 192.168.1.105:4444 · T1071 (Command and Control)
100601 → level 13 · 120sn icinde 5+ baglanti (portlar 4444-4448 korele edildi) · beaconing
```

MITRE eşlemesi otomatik geldi: **Command and Control / Application Layer Protocol (T1071)**.

## Karşılaşılan sorunlar ve çözümleri (gerçek detection engineering)

**1) Kural hiç tetiklenmedi — çift ters bölü + `\\+` yazım hatası.**
İlk deploy'da 100600 sessiz kaldı. Zinciri sırayla ölçtük:
- Üretim: LABPC1'de Event 3 **var** (powershell→.105:4444). ✅
- Ulaşım + grup: koşulsuz bir **tanı kuralı** (if_group sysmon + Event 3) koyduk → tetiklendi,
  yani olay ulaşıyor ve `if_group` çalışıyor. ✅
- Eşleşme: alarmın **ham `image`** değerine baktık — `windows_eventchannel` decoder'ı ters
  bölüleri çiftliyor (`C:\\Windows\\...\\powershell.exe`). Kuraldaki regex ise yanlışlıkla
  `\+` (kaçışlı artı) olmuştu (dosyaya yazılırken bir ters bölü düşmüş). **Çözüm:** regex'i
  `\\+` (kaçışlı ters bölü, bir/daha fazla) yaptık → eşleşti. *(Aşama 14'teki ters-bölü
  dersinin aynısı; eventchannel yol/registry alanlarında daima `\\+` kullan.)*

**2) Beaconing (100601) tetiklenmedi — Sysmon tekilleştirmesi.**
6 bağlantı yaptık ama Wazuh'a **1 Event 3** geldi: Sysmon, **aynı süreç → aynı IP:port**
hızlı tekrarlarını tekilleştirir. Beacon eşiği (5+) dolmadı. **Çözüm:** bağlantıları
**farklı portlara** (4444–4449) çevirdik → her biri ayrı olay → 5+ olay → 100601 düştü.
*Mülakat notu: EDR/Sysmon tekilleştirmesi beacon hacmini gizleyebilir; korelasyonu buna
göre tasarla.*

> **Debug zinciri (ezberle):** bir kural tetiklenmiyorsa sebep dörtten biri —
> **üretim → iletim → ulaşım → eşleşme.** Her birini sırayla ele; tahmin etme, **ölç**.

## Önlem (savunma)
- **Uygulama/süreç ağ kısıtlaması:** powershell/rundll32 gibi LOLBin'lerin keyfî dış
  bağlantısını firewall/EDR ile engelle (yalnız bilinen hedefler).
- **Egress filtreleme:** ağdan çıkışı denetle; bilinmeyen hedef/portlara giden trafiği kes.
- **Beaconing analitiği:** düzenli aralık + sabit hedef desenini (jitter'a rağmen) ara.
- **TLS inceleme / proxy:** şifreli C2'de desen ve hedef itibarını (reputation) değerlendir.

## MITRE ATT&CK
| Teknik | Taktik | Kural |
|--------|--------|-------|
| **T1071** Application Layer Protocol | Command and Control | 100600 / 100601 |

## Ekran görüntüleri
> Wazuh'ta **100600** (powershell→4444) ve **100601** (beaconing, `previous_output`'ta
> korele bağlantılar) alarmlarının ekran görüntülerini `gorseller/` altına ekle.

---

## 🎓 Mülakat / sınav notları
- **C2 nedir?** → Ele geçmiş makine ile saldırgan sunucusu arasındaki uzaktan yönetim kanalı (TA0011).
- **Reverse shell vs beacon?** → Reverse shell = sürekli açık hat (gürültülü); beacon = aralıklı check-in (gizli, modern standart).
- **C2'yi hangi olayla yakalarsın?** → Sysmon Event 3; özellikle powershell/rundll32 gibi süreçlerin dışarı çıkması + beaconing deseni.
- **C2 tespiti neden FP'ye yatkın?** → Her uygulama ağ bağlantısı açar; "bağlantı var" değil "beklenmedik süreç / beacon deseni" aranır.
- **Beacon hacmi neden az loglanabilir?** → Sysmon/EDR aynı 5-tuple tekrarlarını tekilleştirir; korelasyonu buna göre kur.
