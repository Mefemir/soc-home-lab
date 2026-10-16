# Aşama 17 — Exfiltration / DNS Tunneling Tespiti

> ✅ Tamamlandı — saldırganın veriyi DNS sorgularının içine gizleyerek dışarı sızdırması
> (DNS tunneling) LABPC1'de zararsız olarak simüle edildi, **Sysmon Event 22 (DNS query)**
> ile yakalandı ve üç özel Wazuh kuralıyla doğrulandı: **100700** (şüpheli süreç DNS sorgusu,
> level 6), **100701** (yüksek hacim / veri sızdırma, level 13) ve **100702** (uzun/kodlanmış
> subdomain, level 12). Aşama 8'deki MITRE kapsam haritasındaki **Exfiltration (TA0010)**
> boşluğu bu aşamayla kapandı.

## Exfiltration nedir?

Saldırgan içeri girip (Aşama 5-7), kalıcı olup (14) ve uzaktan yönetmeye başladıktan (15)
sonra amacının çoğu zaman son adımı: **değerli veriyi ele geçmiş ağdan dışarı taşımak** —
belgeler, kimlik bilgileri, veritabanı dökümleri. Buna **exfiltration (veri sızdırma)** denir.
MITRE ATT&CK taktiği: **TA0010**. Kill-chain'in genelde sonudur ve savunmanın **son hattıdır**:
saldırgan her şeyi atlatsa bile, veri çıkarken yakalanırsa hasar önlenir.

## Neden DNS tunneling?

DNS bir ağda **neredeyse her zaman açıktır** ve dışarı çıkabilir — firewall HTTP'yi
filtreleyebilir ama DNS'i genelde serbest bırakır. Dahası DNS **özyinelemeli** çözümlenir:
iç DNS sunucusu, bilmediği bir alan adını kök → yetkili sunucuya kadar sorar. Saldırgan bir
alan adının (`exfil.saldirgan.com`) **yetkili DNS sunucusunu kendi kontrol ederse**, içeriden
çıkan her sorgu — firewall'u hiç delmeden — eninde sonunda saldırgana ulaşır.

**Nasıl çalışır:** Çalınacak veri küçük parçalara bölünür, her parça base64/hex ile kodlanıp
bir **alt alan adı (subdomain) etiketi** olarak sorgulanır:
```
<kodlanmis-veri-parcasi>.exfil.saldirgan.com
```
Saldırganın yetkili sunucusu sorguları alır, subdomain'leri çözüp veriyi **yeniden birleştirir**.
Cevap da (komut/onay) TXT/NULL kayıtlarına gizlenebilir → çift yönlü kanal.

## Parmak izi (tespit sinyalleri)

| Sinyal | Neden şüpheli |
|--------|---------------|
| Aynı üst alan adına **çok sayıda** sorgu | Normal site birkaç sorgu yapar; tünel yüzlerce (veri hacmi) |
| **Uzun, rastgele/yüksek-entropili** subdomain | Kodlanmış veri (base64/hex) |
| **TXT / NULL** kayıt yoğunluğu | Çift yönlü veri taşımaya uygun |
| **Beklenmedik sürecin** DNS sorgusu (powershell, özel exe) | Normal DNS'i svchost/tarayıcı yapar |

## Biz nasıl yakaladık? — Sysmon Event 22

Ana kanıt **Sysmon Event 22 — DNS Query**: bir sürecin hangi alan adını sorguladığı.
Alanlar: `image` (hangi süreç), `queryName` (sorgulanan ad), `queryResults`.

> **Önemli:** Event 22, sorgu **başarılı olmasa bile** (NXDOMAIN) loglanır — süreç DNS'e
> sorduğu anda üretilir. Bu yüzden lab'da var olmayan alan adlarını sorgulamak yeterli;
> gerçek bir tünel sunucusu kurmaya gerek yok, hiç veri dışarı çıkmaz.

## Ne yaptık (adımlar)

1. **Keşif:** LABPC1'de Sysmon'un Event 22 ürettiğini doğruladık.
2. **Saldırı simülasyonu (LABPC1):** PowerShell ile (a) 12 farklı kısa subdomain'e DNS sorgusu
   (yüksek hacim), (b) 40 karakterlik rastgele kodlanmış subdomain'ler — hepsi var olmayan
   alan adları (NXDOMAIN, gerçek veri çıkmaz).
3. **Üç katmanlı özel kural** yazıp güvenli deploy ettik (yedek → `wazuh-analysisd -t` →
   hata olursa geri alma → restart).
4. **Doğrulama:** 100700 (level 6), 100701 (level 13), 100702 (level 12) gerçek olaylarla düştü.

### Özel tespit kuralları
> Kuralların nasıl yazıldığını adım adım anlatan genel rehber için →
> [Aşama 05 — Wazuh kuralı nasıl yazılır?](../05-brute-force/#wazuh-kuralı-nasıl-yazılır-bu-repodaki-ilk-kural-burada)

`/var/ossec/etc/rules/local_rules.xml`:
```xml
<group name="sysmon,exfiltration,dns,attack,">

  <!-- 100700: Supheli surec DNS sorgusu yapti - TABAN (T1071.004) -->
  <rule id="100700" level="6">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID">^22$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\+(powershell|powershell_ise|cmd|rundll32|mshta|wscript|cscript|regsvr32|certutil|nslookup)\.exe$</field>
    <description>Supheli surec DNS sorgusu yapti - $(win.eventdata.image) -> $(win.eventdata.queryName) (T1071.004)</description>
    <mitre><id>T1071.004</id></mitre>
    <group>dns,exfiltration,</group>
  </rule>

  <!-- 100701: Yuksek hacim - 60sn icinde 8+ sorgu = veri sizdirma -->
  <rule id="100701" level="13" frequency="8" timeframe="60">
    <if_matched_sid>100700</if_matched_sid>
    <description>DNS tunneling suphesi: supheli surec 60sn icinde 8+ DNS sorgusu yapti (yuksek hacim - veri sizdirma deseni) (T1048)</description>
    <mitre><id>T1048</id></mitre>
    <group>dns,exfiltration,</group>
  </rule>

  <!-- 100702: Cok uzun/kodlanmis subdomain - tek olay, yuksek guven -->
  <rule id="100702" level="12">
    <if_sid>100700</if_sid>
    <field name="win.eventdata.queryName" type="pcre2">(?i)[a-z0-9]{25,}\.</field>
    <description>DNS tunneling suphesi: supheli surec cok uzun/kodlanmis subdomain sorguladi - $(win.eventdata.queryName) (T1048)</description>
    <mitre><id>T1048</id></mitre>
    <group>dns,exfiltration,</group>
  </rule>

</group>
```

### Kuralı parça parça
| Satır | Ne yapar |
|-------|----------|
| `<rule id="100700" level="6">` | **Taban:** şüpheli süreç DNS sorgusu yaptı (tek başına gürültü yapmasın diye düşük seviye) |
| `<if_group>sysmon</if_group>` + `<field ...eventID>^22$</field>` | Sysmon **Event 22** (DNS query) |
| `<field name="win.eventdata.image" type="pcre2">(?i)\\+(powershell\|...\|nslookup)\.exe$</field>` | Sorguyu yapan **şüpheli ikili** mi? `\\+` = bir/daha fazla ters bölü (eventchannel çiftler), `\.exe$` = yol bununla bitiyor |
| `<rule id="100701" frequency="8" timeframe="60">` + `<if_matched_sid>100700</if_matched_sid>` | **Hacim korelasyonu:** 60 sn'de 8+ şüpheli DNS sorgusu = tünel |
| `<rule id="100702" level="12">` + `<if_sid>100700</if_sid>` + `queryName {25,}` | **Uzun subdomain:** 25+ karakterlik kodlanmış etiket = tek olayda yüksek güven |

## Doğrulama (gerçek kanıt)
```
100700 → level 6  · powershell.exe şüpheli DNS sorgusu (10 kez)
100701 → level 13 · 60sn icinde 8+ DNS sorgusu (yuksek hacim) · T1048
100702 → level 12 · powershell.exe -> brlruvkrqhbcjflvpjvxowownzvqnijtkzcgdhvb.exfil.lab (40 karakter kodlanmis) · T1048
```

## FP/BTP uyarısı (kritik)

DNS meşru olarak da gürültülüdür:
- **CDN'ler** (Akamai, Cloudflare) uzun/rastgele subdomain kullanır → tünel gibi görünür ama **BTP**.
- Antivirüs/telemetri bulut sorguları çok sayıda DNS üretir.

Bu yüzden kurallar **"çok DNS var"** demez; **süreç bağlamı** (powershell/nslookup vs tarayıcı)
+ **anormal uzunluk** + **hacim** kombinasyonuna bakar. Örnek: `chrome.exe`'nin `akamai.net`'e
uzun DNS sorgusu = **BTP** (meşru tarayıcı + bilinen CDN); aynı deseni `powershell` bilinmeyen
bir alana yapsa = **TP adayı**. Triyaj için bkz. [Aşama 11](../11-alarm-triyaji/).

> **Kuralın sınırı (dürüst not):** 100700 süreç-merkezlidir (powershell/nslookup...). Kendi
> DNS istemcisini kullanan özel bir tünel aracı bu listeye girmezse kaçabilir; tam kapsam için
> hacim/entropi tabanlı, süreçten bağımsız bir ikinci kural da eklenebilir.

## Önlem (savunma)
- **DNS'i tek bir iç resolver'a zorla**, doğrudan dış DNS çıkışını engelle (egress kontrol).
- **DNS log/analitiği:** sorgu hacmi, subdomain uzunluğu/entropisi, alışılmadık kayıt türleri (TXT/NULL).
- **Alan adı itibarı (reputation)** ve yeni-kayıtlı alan adlarını filtrele.
- **DLP** ile hassas verinin ağdan çıkışını izle.

## MITRE ATT&CK
| Teknik | Taktik | Kural |
|--------|--------|-------|
| **T1071.004** Application Layer Protocol: DNS | Command and Control | 100700 |
| **T1048** Exfiltration Over Alternative Protocol | Exfiltration | 100701 / 100702 |

## Ekran görüntüleri
> Wazuh'ta **100701** (yüksek hacim) ve **100702** (uzun subdomain, `queryName` görünür)
> alarmlarının ekran görüntülerini `gorseller/` altına ekle.

---

## 🎓 Mülakat / sınav notları
- **Exfiltration nedir?** → Veriyi ele geçmiş ağdan dışarı taşıma (TA0010); savunmanın son hattı.
- **Neden DNS tunneling?** → DNS engellenmez ve özyineleme ile saldırganın yetkili sunucusuna ulaşır; veri subdomain etiketlerine gizlenir.
- **Hangi olayla yakalarsın?** → Sysmon Event 22; şüpheli süreç + aynı üst alana yüksek hacim + uzun/rastgele subdomain + TXT/NULL.
- **Neden FP'ye yatkın?** → CDN/telemetri de uzun/çok DNS üretir; "çok sorgu" değil "beklenmedik süreç + anormal desen + hacim" aranır.
- **Event 22 sorgu çözülmese de loglanır mı?** → Evet; süreç DNS'e sorduğu anda üretilir (NXDOMAIN dahi olsa) — tespit istemci tarafında çalışır.
