# Aşama 3 — Loglama ve Sysmon

> ✅ Tamamlandı.

## Neden loglama? Sysmon nedir?

Bir saldırıyı **tespit edebilmen için, saldırının iz bırakması** gerekir. Windows'un
varsayılan logları çoğu zaman yetersizdir — örneğin hangi sürecin hangi komutla,
kim tarafından başlatıldığını detaylı göstermez. Bu aşamanın amacı, **görünürlüğü
(visibility) artırmak**: daha fazla ve daha zengin log üretmek.

**Sysmon (System Monitor)**, Microsoft Sysinternals'ın ücretsiz aracıdır. Bir Windows
servisi olarak çalışır ve normalde görünmeyen **düşük seviyeli sistem olaylarını**
(süreç oluşturma + hash + komut satırı, ağ bağlantıları, uzak thread enjeksiyonu, dosya
oluşturma...) kendi olay kanalına yazar: `Microsoft-Windows-Sysmon/Operational`.

**SwiftOnSecurity config:** Sysmon'u sıfırdan yapılandırmak zordur; topluluğun hazırladığı
bu yapılandırma dosyası, gürültüyü eleyip anlamlı olayları toplayan sağlam bir başlangıçtır.

## Anahtar Event ID'ler (ezberlenmeli)

### Sysmon olayları (`Microsoft-Windows-Sysmon/Operational`)
| ID | Olay | Neden önemli |
|----|------|--------------|
| **1** | Süreç oluşturma | Komut satırı + **hash** + ebeveyn süreç → en değerli olay |
| **3** | Ağ bağlantısı | Hangi süreç nereye bağlandı (C2 tespiti) |
| **8** | CreateRemoteThread | Kod enjeksiyonu (Mimikatz, process injection) |
| **11** | Dosya oluşturma | Dropper, zararlı dosya yazımı |

### Windows Security olayları (denetim açılınca)
| ID | Olay |
|----|------|
| **4688** | Süreç oluşturma (komut satırıyla) — Windows'un yerlisi |
| **4624 / 4625** | Başarılı / başarısız oturum açma |
| **4769** | Kerberos servis bileti isteği (Kerberoasting) |

## Ne yaptık (adımlar)

1. **Sysmon kurulumu** — DC01 ve LABPC1'e SwiftOnSecurity config ile Sysmon yükledik:
   ```powershell
   Sysmon64.exe -accepteula -i sysmonconfig-export.xml
   # config güncelleme:
   Sysmon64.exe -c sysmonconfig-export.xml
   ```
2. **Wazuh'a Sysmon kanalını tanıttık** — her iki makinede `ossec.conf`'a ekledik:
   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```
3. **Gelişmiş denetim politikasını açtık (GPO ile)** — süreç oluşturma komut satırı,
   oturum açma, Kerberos bilet işlemleri vb. (Türkçe sunucuda: *Bilgisayar
   Yapılandırması → İlkeler → Windows Ayarları → Güvenlik Ayarları → Gelişmiş Denetim
   İlkesi Yapılandırması*).
4. **Doğruladık:**
   ```cmd
   auditpol /get /category:*
   ```
   Önce hepsi "No Auditing" idi; ayarlardan sonra "Success and Failure" oldu.

## Karşılaşılan sorunlar ve çözümleri

- **Sysmon satırı sessizce eklenmedi:** PowerShell `-replace '</ossec_config>\s*$'`
  regex'i "eklendi" dedi ama aslında eklememişti. Çözüm: `$raw.LastIndexOf('</ossec_config>')`
  + `Insert()` ile kesin konuma yerleştirdik, satır 219'da doğruladık.
  → **Ders: "güven ama doğrula"** — bir komut "başarılı" dese bile sonucu teyit et.
- **Türkçe sunucu menüleri:** GPO yolları Türkçeye çevrildi (Gelişmiş Denetim İlkesi
  Yapılandırması vb.).

## SOC / mavi takım gözüyle

- **Sysmon Event 1 vs Windows 4688:** İkisi de süreç oluşturmayı gösterir, ama Sysmon 1
  **hash** ve daha zengin alan verir (dosya imzası, ebeveyn komut satırı). İkisini birden
  toplamak en iyisidir.
- **Görünürlük = tespit tavanı:** Toplamadığın log, yazamayacağın kuraldır. Bir tespit
  mühendisi önce "bu saldırı hangi olayı üretir, o olayı topluyor muyum?" diye sorar.

---

## 🎓 Mülakat / sınav notları

- **Sysmon neden kurulur, Windows logu yetmez mi?** → Sysmon hash, komut satırı, ağ
  bağlantısı, enjeksiyon gibi yerli logların vermediği derinliği sağlar.
- **4688 için ne gerekir?** → "Audit Process Creation" denetimi + komut satırını loglamak
  için ayrı bir GPO ayarı ("Include command line in process creation events").
- **Log kaynağı doğrulaması nasıl yapılır?** → `auditpol /get`, `Get-WinEvent -ListLog`,
  ve SIEM tarafında olayların gerçekten geldiğini kontrol.
- **En kıymetli tek olay?** → Süreç oluşturma + komut satırı (Sysmon 1 / 4688); çoğu
  saldırı burada görünür.
