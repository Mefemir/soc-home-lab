# Aşama 5 — Brute-force Tespiti

> ✅ Tamamlandı.

## Brute-force nedir?

**Brute-force (kaba kuvvet)** saldırısı, bir hesabın parolasını **deneme-yanılmayla**
bulmaya çalışmaktır: saldırgan aynı kullanıcı için yüzlerce/binlerce parola dener.
Türleri:
- **Klasik brute-force:** Tek hesaba çok parola.
- **Password spraying:** Çok hesaba az (yaygın) parola — hesap kilitlemeyi atlatmak için.
- **Credential stuffing:** Başka sızıntılardan çalınan kullanıcı/parola çiftlerini denemek.

Windows'ta her başarısız giriş **Event ID 4625**, her başarılı giriş **4624** üretir.
Tespitin özü: **kısa sürede çok sayıda 4625** görmek — ve ardından **aynı kaynaktan bir
4624** gelirse, "saldırı başarılı olmuş olabilir" demektir.

## Anahtar terimler ve Event ID'ler

| Öğe | Anlamı |
|-----|--------|
| **4625** | Başarısız oturum açma |
| **4624** | Başarılı oturum açma |
| **Logon Type** | 2=konsol, 3=ağ, 10=RDP — saldırı vektörünü gösterir |
| **Eşik (threshold)** | "X dakikada N deneme" → alarm sınırı |
| **frequency / timeframe** | Wazuh'ta "N olay / T saniye" korelasyon parametreleri |
| **if_matched_sid** | "Şu kural N kez tetiklenirse" — korelasyonun temeli |

## Ne yaptık (adımlar)

1. Başarısız giriş olaylarını (**4625**) Wazuh'ta izledik. Wazuh'un hazır **rule 60122**
   kuralı tek tek başarısızlıkları yakalıyordu ama bir "saldırı" resmi çizmiyordu.
2. **Özel korelasyon kuralı (100100)** yazdık: 120 saniyede 5 başarısız deneme → **level 10**.
   ```xml
   <group name="windows,authentication_failures,">
     <rule id="100100" level="10" frequency="5" timeframe="120">
       <if_matched_sid>60122</if_matched_sid>
       <description>Brute Force: kisa surede cok sayida basarisiz Windows oturum acma denemesi.</description>
       <mitre><id>T1110</id></mitre>
     </rule>
   </group>
   ```
3. Saldırıyı LABPC1'den tetikledik; **level 10 alarm** düştü.

## Karşılaşılan sorunlar ve çözümleri

- **Korelasyon ilk başta tetiklenmedi:** Varsayılan `authentication_failures` (40111)
  Windows ağ oturumlarında srcip'i ilişkilendirmiyordu. Çözüm: `if_matched_sid 60122`
  tabanlı özel kural + manager restart sonrası **120 sn içinde 10+ hızlı deneme**.
- **Saldırıyı LABPC1'den yaptım ama alarm DC01'de çıktı — neden?** Çünkü ağ oturum
  açma (logon type 3) kimlik doğrulaması **DC üzerinde** gerçekleşir; 4625 olayı
  domain hesabı için DC'de üretilir.

## Bonus: Yanlış pozitif (FP) ayıklama — "güven ama doğrula"

Bir sabah cihazlar açılır açılmaz **level 12 alarm** düştü: Sysmon olayında (rule 61640)
`explorer.exe` şüpheli görünüyordu. Panik yapmadan **kanıta** gittik:
```powershell
Get-AuthenticodeSignature C:\Windows\explorer.exe   # imza geçerli mi?
Get-FileHash C:\Windows\explorer.exe                # hash bilinen iyi mi?
```
İmza **Valid**, hash eşleşti → bu **meşru** bir explorer.exe'ydi, yani **yanlış pozitif**.
Ebeveyni güvenilir sistem süreçleriydi (`winlogon`/`svchost`/`userinit`). Bastırma kuralı
(level 0) yazdık:
```xml
<rule id="100200" level="0">
  <if_sid>61640</if_sid>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)(winlogon|svchost|userinit)\.exe$</field>
  <description>Benign: explorer.exe guvenilir sistem ebeveyninden - FP bastirildi</description>
</rule>
```
→ **Ders:** Her alarmı önce **kanıtla** doğrula (imza, hash, ebeveyn süreç). Meşruysa,
gelecekte gürültü yapmaması için **hedefli** bir bastırma kuralı yaz (kanalı tamamen
kapatma — sadece bilinen iyi deseni sustur).

## SOC / mavi takım gözüyle

- **Eşik seçimi** bir denge sanatıdır: çok düşük → FP seli; çok yüksek → saldırıyı kaçırma.
- **4625 ardından 4624 (aynı IP):** en kritik senaryo — saldırı başarıya ulaşmış olabilir,
  öncelikli incelenir.
- **Logon Type** her zaman kontrol edilir: Type 3 (ağ) ve Type 10 (RDP) saldırılarda yaygın.

---

## 🎓 Mülakat / sınav notları

- **Eşiği neye göre seçtin?** → Ortamın normaline göre (baseline). Önce logları izleyip
  normal hata oranını ölç, eşiği onun belirgin üstüne koy.
- **Şifresini unutan kullanıcıyı saldırgandan nasıl ayırırsın?** → Hız/hacim (insan 3-4
  dener, bot yüzlerce), kaynak IP, saat, farklı hesaplara yayılma (spraying), başarı sonrası
  davranış.
- **Brute-force MITRE?** → **T1110** (alt teknikler: Password Guessing, Password Spraying,
  Credential Stuffing).
- **Hesap kilitleme politikası tespiti nasıl etkiler?** → Saldırgan kilitlemeyi atlatmak
  için spraying'e döner; bu yüzden "çok hesap × az parola" desenini de izlemek gerekir.

## Ekran görüntüleri

**Ham kanıt — kısa sürede çok sayıda 4625 başarısız oturum açma (kural 60122):**

![Başarısız oturum açma seli](gorseller/05-basarisiz-logon.png)

**Tespit — özel kural 100100 tetiklendi (brute-force, level 10):**

![Kural 100100 brute-force alarmı](gorseller/05-rule-100100.png)
