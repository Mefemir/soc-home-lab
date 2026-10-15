# Aşama 14 — Persistence (Kalıcılık) Tespiti

> ✅ Tamamlandı — saldırganın yeniden başlatma sonrası erişimini koruduğu iki yaygın
> teknik (**Registry Run key — T1547.001** ve **Scheduled Task — T1053.005**) LABPC1'de
> simüle edildi, Sysmon olaylarıyla yakalandı ve iki özel Wazuh kuralıyla **level 12**
> alarm olarak doğrulandı. Aşama 8'deki MITRE kapsam haritasındaki **Persistence boşluğu**
> bu aşamayla kapandı.

## Persistence nedir?

Saldırgan bir makineye eriştiğinde, **sistem yeniden başlasa veya kullanıcı oturum
kapatsa bile erişimini korumak** ister. Baştan sömürü (exploit) yapmak zahmetli ve
risklidir. **Persistence (kalıcılık)**, bu "arka kapıyı açık tutma" mekanizmalarıdır ve
kill-chain'de saldırganın ilk ayağını bastıktan hemen sonra yaptığı işlerden biridir.
MITRE ATT&CK'te koca bir taktiktir (TA0003).

### Bu aşamada ele alınan iki teknik

| Teknik | MITRE | Nasıl çalışır | Bıraktığı iz |
|--------|-------|---------------|--------------|
| **Registry Run Keys** | **T1547.001** | Açılışta otomatik çalışacak komut `...\CurrentVersion\Run` anahtarına yazılır | **Sysmon Event 13** (RegistryValueSet) |
| **Scheduled Task** | **T1053.005** | Açılışta/periyodik tetiklenen zamanlanmış görev oluşturulur | **Sysmon Event 1** (`schtasks.exe /create`) + Event 4698 |

> Diğer yaygın persistence teknikleri: Windows Service (T1543.003), WMI Event
> Subscription (T1546.003). Bunlar ileride genişletilebilir.

## Anahtar olaylar (tespitin temeli)

| Event | Kaynak | Ne gösterir |
|-------|--------|-------------|
| **Sysmon Event 13** | `...Sysmon/Operational` | Registry değeri yazıldı (`targetObject`, `details`) |
| **Sysmon Event 1** | `...Sysmon/Operational` | Süreç oluştu (`image`, `commandLine`) — `schtasks.exe` buradan yakalanır |

## Ne yaptık (uygulama)

### 1) Saldırı simülasyonu (LABPC1)
Zararsız bir payload (`echo pwned`'in base64'ü) kullanıldı; amaç tespit, zarar değil.

```cmd
:: Registry Run key persistence (T1547.001)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater ^
  /t REG_SZ /d "powershell -enc ZQBjAGgAbwAgAHAAdwBuAGUAZAA=" /f

:: Scheduled task persistence (T1053.005)
schtasks /create /sc onlogon /tn "WinUpdateCheck" ^
  /tr "powershell -enc ZQBjAGgAbwAgAHAAdwBuAGUAZAA=" /f
```

> **Öğretici ayrıntı:** `schtasks` komutu "Erişim engellendi" ile görevi *oluşturamasa*
> bile tespit düştü — çünkü **Sysmon Event 1, `schtasks.exe` sürecinin başlatıldığını**
> loglar; komutun başarılı olup olmaması tespiti değiştirmez. Saldırganın *niyetini*
> erkenden yakalarız.

### 2) Özel tespit kuralları (iki katmanlı tasarım)
`/var/ossec/etc/rules/local_rules.xml`:
```xml
<group name="sysmon,persistence,attack,">

  <!-- TABAN: Run key'e herhangi bir yazma (mesru yazilim da tetikler -> level 8) -->
  <rule id="100500" level="8">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID">^13$</field>
    <field name="win.eventdata.targetObject" type="pcre2">(?i)\\+CurrentVersion\\+Run(Once)?\\+</field>
    <description>Persistence: Registry Run anahtarina yazma (T1547.001)</description>
    <mitre><id>T1547.001</id></mitre>
  </rule>

  <!-- YUKSEK: Run key komutu supheliyse (powershell/-enc/temp...) -> level 12 -->
  <rule id="100501" level="12">
    <if_sid>100500</if_sid>
    <field name="win.eventdata.details" type="pcre2">(?i)(powershell|cmd\.exe|-enc|-encodedcommand|\\+temp\\+|\\+appdata\\+|mshta|rundll32|regsvr32|\.vbs|\.js|certutil|bitsadmin)</field>
    <description>Persistence (YUKSEK): Supheli Run key komutu (T1547.001)</description>
    <mitre><id>T1547.001</id></mitre>
  </rule>

  <!-- TABAN: schtasks /create -->
  <rule id="100510" level="8">
    <if_group>sysmon</if_group>
    <field name="win.system.eventID">^1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\+schtasks\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/create</field>
    <description>Persistence: Zamanlanmis gorev olusturuldu (T1053.005)</description>
    <mitre><id>T1053.005</id></mitre>
  </rule>

  <!-- YUKSEK: supheli scheduled task -->
  <rule id="100511" level="12">
    <if_sid>100510</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(powershell|-enc|-encodedcommand|\\+temp\\+|\\+appdata\\+|mshta|rundll32|regsvr32|/sc onlogon|/sc onstart|/ru system)</field>
    <description>Persistence (YUKSEK): Supheli zamanlanmis gorev (T1053.005)</description>
    <mitre><id>T1053.005</id></mitre>
  </rule>

</group>
```

**İki katmanlı mantık (Aşama 11 triyajının kurala gömülmesi):** Taban kural (level 8)
*gördüğünü* söyler ama alarm seline yol açmaz — meşru yazılım da Run key/scheduled task
kullanır (BTP). Komutta saldırgan deseni (`powershell -enc`, geçici dizin...) varsa kural
**level 12'ye yükselir** (TP adayı). Böylece OneDrive/Teams gibi meşrular taban seviyede
kalır, gerçek tehdit öne çıkar.

### 3) Doğrulama (gerçek alarm kanıtı)
| Kural | Teknik | Seviye | Tetiklendi | Kanıt |
|-------|--------|--------|-----------|-------|
| **100501** | T1547.001 | 12 | ✅ 1 kez | `reg.exe → ...\CurrentVersion\Run\Updater` ← `powershell -enc ...` |
| **100511** | T1053.005 | 12 | ✅ 1 kez | `schtasks /create /sc onlogon ... powershell -enc ...` |

> Not: Wazuh zincirleme kuralda yalnızca **final** kuralı loglar; bu yüzden taban kurallar
> (100500/100510) alarm sayısında "0" görünür — olay onlarla eşleşip çocuk kurala (12)
> yükseldiği için normaldir.

## Karşılaşılan sorunlar ve çözümleri

- **Scheduled task tespiti ilk denemede düştü, ama Run key tespiti düşmedi.** Sistematik
  teşhis yaptık:
  1. LABPC1'de `Get-WinEvent` ile baktık → Event 13 **üretilmiş** (Sysmon çalışıyor).
  2. Ajan `ossec.conf`'unda Sysmon kanalında **filtre yok** → olay Wazuh'a iletiliyor.
  3. Geçici tanı kuralı (`if_group sysmon` + Event 13, koşulsuz) → **tetiklendi** →
     olay manager'a ulaşıyor ve grup eşleşmesi doğru.
  4. Alarmın ham `targetObject`'ine baktık → değer **çift ters bölü** içeriyordu:
     `...CurrentVersion\\Run\\Updater`.
- **Kök neden:** `windows_eventchannel` decoder'ı ters bölüleri **çiftler** (`\\`). Benim
  regex'im tek ters bölü (`\CurrentVersion\Run\`) arıyordu → eşleşmedi.
- **Çözüm:** Regex'te `\\+` (bir ya da daha fazla ters bölü) kullandık → hem tek hem çift
  ters bölüyü yakalar.
  → **Ders:** eventchannel log'larında yol/registry alanlarındaki ters bölüler çiftlenir;
  regex yazarken `\\+` kullanmak kırılganlığı önler. (Klasik bir detection engineering
  tuzağı.)

## SOC / mavi takım gözüyle

- **Persistence'ı yakalamak kalıcı tutunma noktasını söker:** yakalanmazsa, host
  temizlense bile saldırgan açılışta geri gelir.
- **Persistence tespitinde FP/BTP çoktur:** her yazılım kendini açılışa ekler. İki katmanlı
  kural (taban + şüpheli desen) bu gürültüyü yönetmenin pratik yoludur.
- **Aynı olay birden çok anlama gelebilir:** `schtasks` hem persistence hem execution
  olabilir; bağlam (kaynak, komut, zamanlama) belirler.

## Teslim edildi
- [x] Saldırı simülasyonu (Run key + scheduled task) — LABPC1
- [x] İki teknik için iki katmanlı özel kurallar (100500/100501, 100510/100511)
- [x] Gerçek saldırı testiyle doğrulama (100501 + 100511, level 12)
- [x] eventchannel çift-ters-bölü tuzağının teşhisi ve çözümü
- [ ] Ekran görüntüleri (`gorseller/` — 100501 ve 100511 alarmları eklenecek)

## Ekran görüntüleri

> Henüz eklenecek görseller: Wazuh'ta **100501** (Run key, level 12) ve **100511**
> (scheduled task, level 12) alarmlarının ekran görüntüleri.

---

## 🎓 Mülakat / sınav notları
- **Persistence nedir, neden gerekir?** → Yeniden başlatma/oturum sonrası erişimi korumak.
- **En yaygın Windows persistence teknikleri?** → Run key (T1547.001), Scheduled Task
  (T1053.005), Service (T1543.003), WMI subscription (T1546.003).
- **Run key'i hangi olayla yakalarsın?** → Sysmon Event 13 (RegistryValueSet), `targetObject`
  içinde `\CurrentVersion\Run`.
- **Scheduled task kanıtı?** → Sysmon Event 1'de `schtasks /create` + Windows Event 4698.
- **Komut başarısız olsa bile tespit neden düşebilir?** → Sysmon Event 1 süreç başlatmayı
  loglar; komutun sonucu önemli değil.
- **eventchannel regex tuzağı?** → Ters bölüler çiftlenir (`\\`); desende `\\+` kullan.
