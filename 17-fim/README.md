# Aşama 17 — File Integrity Monitoring (FIM)

> ✅ Tamamlandı  LABPC1 ajanında Wazuh `syscheck` modülüyle kritik `hosts` dosyasını
> **gerçek zamanlı (realtime)** izlemeye aldım, zararsız bir pharming simülasyonuyla
> (`hosts`'a sahte DNS yönlendirme satırı) **içerik/hash değişimini canlı yakaladım**.
> Hazır kural **550**'yi (level 7) doğruladıktan sonra, bu kritik dosya için seviyeyi
> **level 12**'ye çıkaran özel kuralımı **100900** yazdım ve ikinci bir değişiklikle
> canlı tetikledim. Konfigürasyonu merkezi `agent.conf` ile dağıttım (profesyonel yöntem).

## File Integrity Monitoring nedir?

Önceki aşamalar hep bir **aktivite** (başarısız giriş, LSASS erişimi, DNS sorgusu) yakaladı.
Ama bazı saldırılar sadece **bir dosyayı sessizce değiştirir**: `System32`'ye zararlı DLL
bırakmak, `hosts`'u değiştirip kurbanı sahte bankaya yönlendirmek (pharming), web köküne
`shell.php` koymak, bir Run key eklemek. **FIM**, izlenen dosya/dizin/registry'nin
**oluşturma / değiştirme / silme** olaylarını tespit eden savunma kontrolüdür. Wazuh'ta
bunu yapan modülün adı **`syscheck`**'tir (ajanın içinde çalışır).

> **Neden kritik:** `hosts`, `System32` gibi dosyalar meşru olarak **neredeyse hiç
> değişmez** → her değişiklik yüksek inceleme değeri taşır. PCI-DSS 11.5, HIPAA, NIST SI.7
> gibi standartlar FIM'i **zorunlu** tutar.

## Nasıl çalışır?  Baseline + hash karşılaştırması

1. **Baseline:** ajan izlenen her dosyanın bir "kimlik kartı"nı çıkarır ve yerel bir
   veritabanına (`fim.db`) yazar: kriptografik **hash** (MD5/SHA-1/SHA-256) + metadata
   (boyut, sahiplik, izinler, mtime).
2. **İzleme:** dosya tekrar kontrol edilir, yeni parmak izi baseline ile karşılaştırılır.
3. **Fark → olay:** hash veya metadata değiştiyse `added` / `modified` / `deleted` olayı
   üretilir ve manager'a gönderilir.

> **Hash = içerik parmak izi.** Tek bir karakter bile değişse SHA-256 tamamen başka çıkar;
> boyut aynı kalsa bile yakalanır. Ayrıca sadece **izin/sahiplik** değişimi de (içerik aynı
> olsa bile) yakalanır  bir saldırganın bir binary'yi `setuid`/yazılabilir yapması gibi.

## Üç çalışma modu

| Mod | Nasıl | Artı / Eksi |
|-----|-------|-------------|
| **Scheduled** (periyodik) | `frequency` aralığında tüm dizini tarar (varsayılan 12 saat) | Düşük kaynak; ama **iki tarama arası değişip geri alınan** şeyi kaçırır |
| **Realtime** | OS'un dosya-değişiklik bildirimini dinler (Windows `ReadDirectoryChangesW`) → değişiklik **anında** yakalanır | Anlık; sadece **dizinler** için |
| **Whodata** | Realtime + değişikliği **kim/hangi süreç** yaptı (Audit/SACL) | En zengin veri; ekstra Audit altyapısı gerekir |

Bu aşamada **realtime** kullandım (kritik dosya için doğru seçim "tarama penceresi"
boşluğu olmuyor). Whodata opsiyonel bir üst katman; Windows'ta ekstra Audit politikası istiyor.

## Ne izlenir, ne izlenmez? (tuning)

FIM **her dosyaya bakmaz, bakmamalı da.** Altın kural: *"Bu dosya meşru sebeple ne sıklıkta
değişir?"* → cevap **"neredeyse hiç"** ise izle.

| İzle ✅ (statik olmalı) | İzleme ❌ (sürekli değişir → gürültü) |
|---|---|
| `hosts`, `System32\drivers\etc` | `Temp`, `%TEMP%`, log dizinleri |
| Sistem binary'leri, DLL | Tarayıcı cache'i |
| Web kök dizini (web shell) | Sürekli yazılan uygulama verisi |
| Registry Run/servis anahtarları | pagefile, DB dosyaları |

Gürültü azaltma araçları: `<ignore>` (alt yolu yok say), `<nodiff>` (değişikliği raporla
ama içerik farkını gizle hassas dosyalar için).

## Kurduğum yapılandırma (merkezi `agent.conf`)

FIM ayarı **ajan tarafında**, ama her ajana elle girmek yerine manager'daki **merkezi paylaşımlı
config** ile `default` grubundaki tüm ajanlara dağıttım gerçek SOC yöntemi.

`/var/ossec/etc/shared/default/agent.conf`:
```xml
<agent_config>
  <!-- kritik 'hosts' dizinini gercek-zamanli izle + icerik farki -->
  <syscheck>
    <directories check_all="yes" realtime="yes" report_changes="yes">C:\Windows\System32\drivers\etc</directories>
  </syscheck>
</agent_config>
```

| Öğe | Anlamı |
|-----|--------|
| `check_all="yes"` | Tüm parmak izini al (hash + boyut + izin + sahiplik + mtime) |
| `realtime="yes"` | Bu dizini gerçek zamanlı izle (anında tespit) |
| `report_changes="yes"` | Metin dosyasında **tam olarak hangi satırın** değiştiğini (diff) raporla |

Dağıtım: manager restart → config `default` grubuna gider → LABPC1 ajanı restart'ta çeker,
`scan_on_start` ile baseline'ı alır, sonra realtime izlemeye başlar.

## Özel tespit kuralı (parça parça)

Hazır kural **550** (`Integrity checksum changed`) sadece **level 7**. `hosts` gibi
asla-değişmemesi-gereken bir dosya için bu, SOC kuyruğunda düşük kalır. Gerçek bir olayın
JSON alanlarını (alan adı `file`, decoder `syscheck_integrity_changed`) **gözlemleyip**
seviyeyi yükselten kuralımı yazdım:

`/var/ossec/etc/rules/local_rules.xml`:
```xml
<group name="syscheck,fim,">
  <rule id="100900" level="12">
    <if_sid>550,553,554</if_sid>
    <field name="file" type="pcre2">(?i)drivers.etc.hosts$</field>
    <description>FIM: kritik 'hosts' dosyasi degisti (olasi pharming/DNS yonlendirme) - $(file)</description>
    <mitre><id>T1565.001</id></mitre>
    <group>fim,attack,pci_dss_11.5,</group>
  </rule>
</group>
```

| Satır | Ne yapar |
|-------|----------|
| `<if_sid>550,553,554</if_sid>` | **Tetikleyici:** hazır FIM kuralları (550 değişti / 553 silindi / 554 eklendi) düştüğünde değerlendir. Yani bu kural onların **daha spesifik çocuğudur** |
| `<field name="file" type="pcre2">(?i)drivers.etc.hosts$</field>` | Olaydaki `file` (syscheck path) alanı `...\drivers\etc\hosts` ile mi bitiyor? `.` ayracı ters-bölü dert etmeden eşler, `(?i)` büyük/küçük harf duyarsız |
| `level="12"` | Hazır 550'in level 7'sini **12'ye yükseltir** (kritik dosya tahrifi ciddi) |
| `$(file)` | Açıklamada değişen dosya yolunu dinamik göster |

> **Tasarım notu:** Kuralı tahminle değil, **gerçek bir FIM olayını gözlemledikten sonra**
> yazdım (C2/DNS aşamalarındaki "ölç, tahmin etme" dersi). Alan adının `file`, grubun
> `syscheck_entry_modified` olduğunu canlı alarmdan doğruladım.

## Kanıt canlı doğrulama

**1) Hazır kural (550, level 7) ilk değişiklik:**
```
agent  : LABPC1 (192.168.1.85)
rule   : 550 (level 7) Integrity checksum changed  →  T1565.001, PCI-DSS 11.5
path   : c:\windows\system32\drivers\etc\hosts     mode: realtime   event: modified
size   : 824 → 879
sha256 : 2d6bdf… → 3f7501…
diff   : > 192.0.2.66  www.bankam-test.local
```

**2) Özel kural (100900, level 12) ikinci değişiklik:**
```
rule   : 100900 (level 12) FIM: kritik 'hosts' dosyasi degisti (pharming/DNS yonlendirme)
path   : c:\windows\system32\drivers\etc\hosts     mode: realtime   event: modified
size   : 879 → 935
sha256 : 3f7501… → 99326a…      (before == birinci olayin after'i → kesintisiz zincir)
diff   : > 192.0.2.77  www.giris-dogrulama.local
mail   : true  (yuksek oncelik)
```

Aynı dosya olayı artık daha spesifik kuralımıza düşüyor (level 7 → **12**). `report_changes`
sayesinde eklenen **sahte yönlendirme satırı birebir** görünüyor pharming'de "hangi
adrese yönlendiriyor" sorusunun cevabı. (Test IP'leri `192.0.2.0/24` RFC 5737 TEST-NET'tir,
routing yapmaz zararsız.)

## FIM sadece TESPİT eder geri almaz (Aşama 18 köprüsü)

Çıkardığım kritik ders: FIM dosyayı **eski haline getirmiyor, değişikliği engellemiyor.** Değişen
`hosts` diskte **yeni haliyle kalıyor**; FIM sadece "değişti" diyor (güvenlik kamerası gibi 
kaydeder, kapıyı kilitlemez). Otomatik geri alma / süreci öldürme / IP bloklama bir sonraki
aşamanın işi: **Aşama 18  Active Response.** Doğru akış bence: **FIM gör → analist/otomasyon
bağlama bak → kötüyse tepki ver.** Makine körlemesine geri alsaydı meşru bir Windows Update'i bile
bozardı  bu yüzden kararı bağlamla veriyorum (defense in depth).

## İş akışı (nasıl kurdum)

1. **Keşif:** ajan durumu (LABPC1/DC01 Active, `default` grubu), boş merkezi `agent.conf`,
   hazır FIM kuralları (550/553/554) doğrulandı.
2. **Deploy:** merkezi `agent.conf`'a `syscheck` bloğu (yedek + `verify-agent-conf` + manager
   restart; hata olsa otomatik geri-alma).
3. **Ajan restart (LABPC1):** yeni config çekildi + `scan_on_start` baseline.
4. **Saldırı simülasyonu:** `hosts`'a zararsız pharming satırı → **550 canlı yakalandı**.
5. **Özel kural:** 100900 (level 12) eklendi (`wazuh-analysisd -t` + geri-alma + restart).
6. **Doğrulama:** ikinci `hosts` değişikliğinde **100900 (level 12)** tetiklendi.

## MITRE ATT&CK
| Teknik | Taktik | Kural |
|--------|--------|-------|
| **T1565.001** Stored Data Manipulation | Impact | 550 (hazır) → **100900** (özel, level 12) |

## Beceriler (bu aşamada kanıtlanan)
`File Integrity Monitoring` · `Wazuh syscheck` · `Realtime FIM` · `Baseline/hash karşılaştırma` ·
`Merkezi agent.conf dağıtımı` · `Hazır kural seviye yükseltme` · `report_changes/diff` ·
`PCI-DSS 11.5` · `Pharming tespiti`
