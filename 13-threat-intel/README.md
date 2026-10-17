# Aşama 13 — Threat Intelligence & IOC Zenginleştirme (CDB Bloklist)

> **Amaç:** Aşama 12'de phishing `.eml`'inden çıkardığımız IOC'leri (kötü IP/domain) bir
> **tehdit istihbaratı bloklist'ine** dönüştürmek ve Wazuh'un gelen her log'da bu listeyle
> otomatik eşleştirme yapmasını sağlamak. Yani: "bu gösterge tanıdık bir kötü aktör mü?"
> sorusunu SIEM'in **otomatik** yanıtlaması.

Bu aşama Wazuh'un **CDB list** mekanizmasını kullanır — API gerektirmez, offline çalışır,
çok hızlıdır. (Canlı dış-API zenginleştirme — VirusTotal/AbuseIPDB — bir sonraki katman,
en altta "Sıradaki" bölümünde.)

---

## 1. Threat Intelligence nedir?

Tehditler hakkında toplanmış, işlenmiş ve **bağlamlandırılmış** bilgidir. Amaç ham bir
göstergeyi (bir IP) **eyleme dönüştürülebilir bilgiye** ("bu IP bilinen bir phishing C2
sunucusu") çevirmek. Üç seviyesi vardır:

| Seviye | Kime | İçerik |
|--------|------|--------|
| **Stratejik** | Yönetici / CISO | Trendler, aktör motivasyonları (teknik değil) |
| **Operasyonel** | SOC lideri / IR | Kampanyalar, aktör TTP'leri, ATT&CK eşleşmeleri |
| **Taktiksel** | **SOC analisti (biz)** | **IOC'ler** — kötü IP/domain/hash/URL, hızlı bloklanır |

Bu aşama **taktiksel TI**: IOC eşleştirme ve otomatik alarm.

### IOC (Indicator of Compromise)
Kötü niyetli aktivitenin teknik kanıtı: **hash** (dosya), **IP** (C2/kaynak),
**domain/URL** (phishing/malware), **e-posta göstergeleri**.

---

## 2. Pyramid of Pain — IOC bloklamanın değeri (ve sınırı)

David Bianco'nun piramidi, bir IOC'yi bloklamanın saldırgana ne kadar "acı" verdiğini gösterir:

```
                  ▲ Saldırgana ZOR (değiştirmesi pahalı)
      ┌───────────────────────┐
      │   TTP (davranışlar)   │  ← En değerli: tekniği yakalarsan aktör çaresiz
      ├───────────────────────┤
      │   Araçlar             │
      ├───────────────────────┤
      │ Ağ/Host artifact'leri │
      ├───────────────────────┤
      │   Domain adları       │
      ├───────────────────────┤
      │   IP adresleri        │  ← Saldırgan 5 dakikada yeni VPS kiralar
      ├───────────────────────┤
      │   Hash değerleri      │  ← Tek bit değişse hash değişir (en kırılgan)
      └───────────────────────┘
                  ▼ Saldırgana KOLAY (anında değiştirir)
```

> **Kritik ders:** IP/hash bloklamak **kolaydır ama saldırgan anında değiştirir.** Bu yüzden
> IOC tabanlı TI **gerekli ama yetersizdir** — asıl kalıcı savunma, Aşama 5–17'de yaptığımız
> **davranış (TTP) tespitidir.** TI, davranış tespitinin **üstüne** eklenen hızlı bir ilk
> filtredir, onun yerine geçmez. Bu aşama bilinçli olarak piramidin tabanıdır.

---

## 3. CDB list nedir, nasıl çalışır?

**CDB (Constant Database)** = Wazuh'un çok hızlı aradığı anahtar-değer listesi. Bilinen-kötü
göstergeleri bir metin dosyasına `key:value` formatında koyarız; Wazuh bunu derler (`.cdb`),
ve bir kural "gelen log'daki IP bu listede mi?" diye **neredeyse O(1)** hızında bakar.

- **Artısı:** çok hızlı, internet/API gerektirmez, rate-limit yok.
- **Format:** her satır `anahtar:değer` → `165.22.86.103:asama12-phishing-gophish-c2`
  (anahtar = eşleştirilen gösterge, değer = bizim için not/etiket).
- **Nerede yaşar:** `/var/ossec/etc/lists/<liste-adı>`, `ossec.conf`'ta `<list>` ile tanımlanır,
  manager restart'ta `.cdb` olarak derlenir.

Bu aşamada iki liste oluşturduk ([`listeler/`](listeler/)):

| Liste | İçerik | Kaynak |
|-------|--------|--------|
| `blocklist-ip` | `165.22.86.103` | Aşama 12 phishing — GoPhish C2 (DigitalOcean VPS) |
| `blocklist-domain` | `updatecenter.com` | Aşama 12 phishing — credential harvesting domain |

> **IOC seçimi dersi:** Aşama 12'de relay IP `173.201.193.231` de vardı ama onu **bilerek
> bloklamadık** — o GoDaddy'nin paylaşımlı mail sunucusu; bloklamak binlerce meşru maili de
> keser (yanlış pozitif). **Her IOC körü körüne bloklanmaz; bağlamıyla değerlendirilir.**

---

## 4. Kurduğumuz kurallar

Üç kural, üç farklı log kaynağı için ([tam blok aşağıda](#kuralları-parça-parça)):

| Kural | Tetikleyici (`if_group`) | Eşleştirdiği alan | Senaryo |
|-------|--------------------------|-------------------|---------|
| **100800** | `authentication_success` | `srcip` | Bilinen-kötü IP'den **başarılı giriş** (çalınan kimlik) |
| **100801** | `fortigate` | `dstip` | İç makine bilinen-kötü IP'ye **bağlandı** (olası C2 — giden trafik) |
| **100802** | `sysmon` + Event 22 | `win.eventdata.queryName` | Bilinen-kötü **domain DNS sorgusu** |

### Kuralları parça parça

```xml
<group name="threat_intel,ioc,">
  <rule id="100800" level="12">
    <if_group>authentication_success</if_group>
    <list field="srcip" lookup="match_key">etc/lists/blocklist-ip</list>
    <description>Threat Intel: bilinen-kotu IP'den basarili giris - $(srcip)</description>
    <mitre><id>T1071</id></mitre>
    <group>threat_intel,ioc_match,</group>
  </rule>
  ...
</group>
```

| Satır | Anlamı |
|-------|--------|
| `<if_group>authentication_success</if_group>` | **Kuralı kural ağacına bağlayan tetikleyici.** "Başarılı kimlik doğrulama" grubundaki olayların (ör. sshd rule 5715) **altında** değerlendir. **Bu satır olmazsa kural hiç denenmez** (bkz. Ders 1) |
| `<list field="srcip" lookup="match_key">etc/lists/blocklist-ip</list>` | Olaydaki `srcip` alanını al, `blocklist-ip` CDB'sinde **anahtar olarak tam eşleşme** ara. Eşleşirse kural tetiklenir |
| `level="12"` | Yüksek seviye alarm (bilinen-kötü gösterge ciddi) |
| `$(srcip)` | Açıklamada eşleşen IP'yi dinamik göster |

**100801** aynı mantık ama `<if_group>fortigate</if_group>` + `dstip` → "iç makineden
bilinen-kötü IP'ye **giden** bağlantı" (C2 tespiti, Aşama 15 ile örtüşür).
**100802** `<if_group>sysmon</if_group>` + `<field name="win.system.eventID">^22$</field>` +
`queryName` → DNS sorgusunda kötü domain (Aşama 17 DNS mantığıyla aynı decoder).

---

## 5. 🔑 Bu oturumda canlı keşfettiğimiz iki ders

### Ders 1 — Atomic `<list>` kuralı tek başına çalışmaz; bir `if_group`/`if_sid` ister
İlk denememizde kural şöyleydi (tetikleyicisiz):
```xml
<rule id="100800" level="12">
  <list field="srcip" lookup="...">etc/lists/blocklist-ip</list>   <!-- if_group YOK -->
</rule>
```
`srcip` doğru decode edilmesine ve CDB'de IP bulunmasına rağmen **kural hiç tetiklenmedi.**
`wazuh-logtest -v` ile "Rule debugging" çıktısına baktık: kural **"Trying rule" listesinde
hiç görünmüyordu** — yani kural ağacına bağlanmamıştı ("orphan").

> **Neden:** Wazuh'ta bir kuralın değerlendirilmesi için ağaca bir **bağlanma noktası**
> gerekir: `<if_sid>`, `<if_group>`, `<decoded_as>` veya bir pre-match pattern. Sadece
> `<list>` içeren kuralın hiçbiri yoktur → asla denenmez. Çözüm: kuralı mantıklı bir gruba
> bağlamak. Nitekim Wazuh'un **kendi** hazır kuralı `99903` ("Authentication succeeded from
> a malicious IP") de tam olarak `<if_group>authentication_success</if_group>` ile bağlıdır.

### Ders 2 — `match_key` vs `address_match_key`
İlk sürümde `lookup="address_match_key"` kullandık (CIDR/subnet semantiği). Tek-host IP
(`165.22.86.103`) için beklediğimiz gibi eşleşmedi. **Tek IP tam eşleşmesi için doğru olan
`match_key`** (anahtarla birebir string eşleşme). `address_match_key`'i subnet/CIDR
bloklarken (`10.0.0.0/8` gibi) kullan.

---

## 6. Kanıt — canlı doğrulama (wazuh-logtest)

```text
# Bilinen-kötü IP'den sshd girişi
$ echo 'sshd[...]: Accepted password for melih from 165.22.86.103 ...' | wazuh-logtest
   id: '100800'
   description: 'Threat Intel: bilinen-kotu IP'den basarili giris - 165.22.86.103'
   >>> 100800 TETIKLENDI — CDB bloklist çalışıyor

# Kontrol: TEMİZ IP (8.8.8.8) ile aynı log
$ echo 'sshd[...]: Accepted password for melih from 8.8.8.8 ...' | wazuh-logtest
   >>> 8.8.8.8 için 100800 tetiklenmedi (doğru — yanlış pozitif yok)
```

Pozitif (kötü IP → alarm) **ve** negatif (temiz IP → sessiz) testlerin ikisi de geçti.

> **Dürüst not:** `100800` canlı `wazuh-logtest` ile deterministik doğrulandı. `100801`
> (FortiGate giden trafik) ve `100802` (Sysmon DNS) kuralları doğru tetikleyicilerle yazıldı
> ama **canlı trafikle** test, ilgili kaynak hazır olduğunda yapılacak (FortiGate şu an kapalı;
> Sysmon testi LABPC1'den DNS üretimiyle Aşama 17'deki gibi yapılabilir).

---

## 7. İş akışı (nasıl kurduk)

1. **Keşif:** mevcut `etc/lists/` ve `ossec.conf` ruleset bloğu okundu (Wazuh'ta zaten
   `malicious-ioc/*` CDB altyapısı vardı).
2. **Listeler:** `blocklist-ip` + `blocklist-domain` yazıldı, `ossec.conf`'a `<list>` tanımları
   eklendi (idempotent).
3. **Kurallar:** `local_rules.xml`'e 100800/100801/100802 eklendi; `wazuh-analysisd -t` ile
   test + hata olursa otomatik geri-alma; manager restart ile CDB derlendi.
4. **Teşhis + düzeltme:** 2 iterasyon (`address_match_key`→`match_key`, sonra `if_group`
   eklenmesi) — `wazuh-logtest -v` rule-debugging ile kök neden bulundu.
5. **Doğrulama:** pozitif + negatif logtest.

---
## Sıradaki katman (opsiyonel) — Canlı dış-API zenginleştirme

Bu aşama **statik CDB bloklist** kurdu. Bir üst katman, Wazuh **Integrator** ile alarm
anında **VirusTotal / AbuseIPDB** API'sine sorup "kaç motor zararlı diyor / abuse skoru kaç"
bilgisini alarma eklemektir. Ücretsiz API anahtarı gerektirir ve rate-limit nedeniyle
**sadece seçili yüksek-seviye alarmlara** bağlanır. İleride eklenebilir.

## Beceriler (bu aşamada kanıtlanan)

`Threat Intelligence` · `IOC yönetimi` · `CDB list` · `Pyramid of Pain` ·
`Wazuh kural ağacı (if_group/if_sid)` · `wazuh-logtest rule-debugging` · `FP bilinci`
