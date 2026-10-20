# Aşama 12 — Şüpheli E-posta (Phishing) Analizi

> **Amaç:** Elimize gelen şüpheli bir e-postayı, **hiçbir şeye tıklamadan / eki
> çalıştırmadan**, ham `.eml` kaynağı üzerinden parçalara ayırıp "zararlı mı, kim
> gönderdi, neyi hedefliyor" sorularını yanıtlamak ve IOC + karar üretmek.
> Bu, bir SOC analistinin kuyruğundaki **en kalabalık ticket türüdür**.

Bu aşama önceki aşamalardan farklı: burada Wazuh kuralı yazmıyorum, **analist el
becerisi** gösteriyorum. Aşama 11'deki TP/FP triyaj mantığı burada doğrudan devrede.
Elimdeki gerçek numune ([`ornekler/actionrequired.eml`](ornekler/actionrequired.eml))
üzerinde teoriyi satır satır uyguluyorum.

---

## 0. Altın kural: E-postayı bir kanıt dosyası gibi ele al

Live Outlook'ta **tıklayarak** değil, ham `.eml` / `.msg` kaynağı üzerinden incelenir. Çünkü:

- Bir **tıklama** = tracking pixel'in "bu adres canlı" sinyali göndermesi.
- Bir **link** = kimlik avı sayfası / drive-by indirme.
- Bir **ek** = makro / yürütülebilir çalışması.

Analiz, olayı **izole** biçimde yapar: linkler defang edilir (`hxxp`, `[.]`), ekler
açılmaz yalnızca hash'lenir, e-posta tercihen bir analiz VM'inde / metin editöründe
açılır.

---

## 1. E-postanın iki katmanı: Zarf (envelope) vs. Başlık (header)

E-posta SMTP ile taşınır; tıpkı fiziksel posta gibi **iki ayrı adres katmanı** vardır
ve phishing'in bütün hilesi bu ikisi arasındaki boşlukta saklanır.

| Katman | İçerik | Kullanıcı görür mü? | Doğrulanır mı? |
|--------|--------|:---:|:---:|
| **Zarf (SMTP envelope)** | `MAIL FROM:` (dönüş yolu), `RCPT TO:`  teslimatı yöneten gerçek adresler. Teslim sonrası `Return-Path`'e yazılır | ❌ | SPF bunu kontrol eder |
| **Başlık + gövde (message)** | `From:`, `To:`, `Subject:`  Outlook'ta görülen alanlar | ✅ | **Hayır  sadece metin** |

> **Kritik:** `From:` başlığını taklit etmek (spoofing), bir mektuba sahte "gönderen"
> yazmak kadar kolaydır. "Kim gönderdi" sorusunun gerçek cevabı `From:`'da değil,
> **`Received` zincirinde + kimlik doğrulama sonuçlarındadır.**

---

## 2. Header analizi  işin kalbi (analizin ~%70'i)

### 2.1 `Received` zinciri  e-postanın pasaportu

Her sunucu e-postaya dokunduğunda **en üste** bir `Received:` satırı ekler.
Zincir **aşağıdan yukarıya** okunur: en alttaki = ilk (kaynak) sunucu, en üstteki =
senin mail sunucun. Aranacaklar:

- **Gerçek kaynak IP'si:** En alttaki `Received: from ... [IP]`. Nereye ait? Coğrafya,
  hosting/VPS mi yoksa meşru kurumsal mı?
- **Mantık kopuklukları:** `From:` tanınmış bir markayı gösteriyor ama kaynak IP bir
  VPS / tanımadık bulk-mail sağlayıcısı → kırmızı bayrak.
- **Güvenilir sınır:** Saldırgan zincirin **altına** sahte `Received` satırı uydurabilir,
  ama senin mail sunucunun eklediği **üst** satırlara dokunamaz  güven oradan aşağı iner.

### 2.2 Kimlik uyuşmazlıkları  en hızlı phishing sinyali

| Kontrol | Ne demek |
|---------|----------|
| `From:` vs `Return-Path` | Farklıysa → klasik spoof / dönüş yolu manipülasyonu |
| `From:` vs `Reply-To` | Farklıysa → BEC / CEO-fraud klasiği ("cevap dolandırıcıya gider") |
| **Display name hilesi** | Görünen ad "Microsoft Hesap Ekibi", gerçek adres `security@random123.com`. Kullanıcı sadece display name'i görür |

### 2.3 Diğer başlıklar
`Message-ID:` (domain `From` ile uyumlu mu?), `X-Mailer:` (gönderen istemci  bazen
aracı ele verir!), `X-Originating-IP`, `Date:` (tutarsızlık).

---

## 3. Kimlik doğrulama: SPF / DKIM / DMARC

Alan sunucusu bu üçlüyü kontrol edip sonucu **`Authentication-Results:`** başlığına yazar.

| Mekanizma | Ne doğrular | Sonuç başlığı |
|-----------|-------------|---------------|
| **SPF** (Sender Policy Framework) | Domain sahibinin DNS'teki "benim adıma şu IP'ler gönderebilir" listesinde, **zarf gönderen IP'si** var mı. **Görünen `From:`'u değil, zarfı doğrular** | `spf=pass` / `fail` |
| **DKIM** (DomainKeys Identified Mail) | Gönderen sunucu e-postayı özel anahtarla **kriptografik imzalar**; alan sunucu DNS'teki açık anahtarla doğrular → içerik yolda değişmedi + o domain imzaladı | `dkim=pass` / `fail` |
| **DMARC** | SPF/DKIM sonucunu **görünen `From:` domain'iyle hizalar (alignment)** + politika belirler (none / quarantine / reject). **Phishing'i asıl yakalayan katman** | `dmarc=pass` / `fail` |

> ⚠️ **En kritik yanılgı:** `spf=pass` **güvenli demek DEĞİLDİR.** Saldırgan kendi
> domain'ini kurup SPF'ini düzgün yapılandırmış olabilir → pass alır ama yine de
> zararlıdır. `pass` = "zarf tutarlı"; "zararsız" demek değil.
> **Bu dersin canlı kanıtı Bölüm 6'daki gerçek numunede.**

---

## 4. URL (link) triyajı  tıklamadan

- **Defang:** Analiz/raporda linkler zararsızlaştırılır: `http` → `hxxp`, `.` → `[.]`.
  Örn: `hxxps://paypa1-secure[.]com/login`. Yanlış tıklamayı önler.
- **Görünen metin vs gerçek hedef:** HTML'de `<a href="http://kötü.com">www.bankam.com</a>`
   kullanıcı "bankam.com" görür, link başka yere gider. Ham kaynakta `href`'e bakılır.
- **Typosquat / homoglyph:** `paypa1.com` (l→1), `rnicrosoft.com` (m→rn),
  `bankam-guvenlik.com` (ek kelime).
- **Redirect / URL kısaltıcı:** `bit.ly/...` veya open-redirect arkasında gizli hedef.
  Tıklanarak değil, URL analiz servisi / sandbox ile çözülür.

---

## 5. Ek (attachment) triyajı  açmadan

- **Tehlikeli uzantılar:** `.exe`, `.scr`, `.js`, `.vbs`, `.hta`, makrolu Office
  (`.docm`, `.xlsm`), `.iso`/`.img` (SmartScreen atlatma), parola korumalı `.zip`
  (parola gövdede verilir → AV atlatma klasiği).
- **Çift uzantı / sahte ikon:** `fatura.pdf.exe`.
- **Hash çıkarma (açmadan):** `Get-FileHash dosya -Algorithm SHA256` → bu hash Threat
  Intel'de (VirusTotal **Aşama 13**) aranır. Dosya asla analiz makinesinde açılmaz.

---

## 6. 🔬 Gerçek numune analizi  `actionrequired.eml`

Numune: [`ornekler/actionrequired.eml`](ornekler/actionrequired.eml) (GoPhish ile
üretilmiş gerçek bir kimlik-avı simülasyonu, 8 Aralık 2023). Teoriyi satır satır
uyguluyorum.

### 6.1 Received zincirini oku (aşağıdan yukarıya)

```text
# EN ALT  kaynak (ilk dokunan sunucu):
Received: from gophish ([165.22.86.103]) by :SMTPAUTH: with ESMTPSA ...
# ORTA  relay:
Received: from p3plsmtpa09-02.prod.phx3.secureserver.net ([173.201.193.231])
          by mx.google.com ...
# EN ÜST  bizim sunucu (Google):
Received: by 2002:a05:... with SMTP id ... (Gmail teslim)
```

| Bulgu | Değer | Yorum |
|-------|-------|-------|
| **Kaynak makine adı** | `gophish` | 🚩 **Smoking gun**  makine resmen "gophish" adlı. GoPhish = açık kaynak phishing kampanya aracı |
| **Kaynak IP** | `165.22.86.103` | DigitalOcean VPS  saldırgan altyapısı, kurumsal mail sunucusu değil |
| **Relay** | `173.201.193.231` (`secureserver.net`) | GoDaddy  saldırgan burada `updatecenter.com` domain'ini satın almış |

### 6.2 Kimlik doğrulama tuzağa dikkat

```text
Received-SPF: pass (... domain of administrator@updatecenter.com designates
              173.201.193.231 as permitted sender) client-ip=173.201.193.231
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=administrator@updatecenter.com
```

- **`spf=pass`** ✅ ... **ama phishing!** Çünkü saldırgan `updatecenter.com` domain'ini
  kendi aldı ve SPF'ini (GoDaddy IP'si `173.201.193.231`) düzgün kurdu. Alan sunucu
  "zarf tutarlı" dedi  **"zararsız" demedi.** İşte Bölüm 3'teki uyarının canlı kanıtı.
- **DKIM / DMARC yok** (yalnızca Google'ın eklediği `ARC-*` var). Meşru kurumsal mail
  neredeyse her zaman DKIM imzalar  yokluğu başlı başına şüphe.

### 6.3 Kimlik uyuşmazlıkları  bu örnekte "kolay" sinyaller TEMİZ

```text
From:        "System Security" <administrator@updatecenter.com>
Return-Path: <administrator@updatecenter.com>      # From ile AYNI
```

- `Return-Path == From` → **uyuşuyor.** Yani bu phishing'i "Return-Path ≠ From"
  tuzağından **yakalayamazsın.** (Saldırganın kendi domain'i olduğu için.)
- **Display name hilesi:** Görünen ad `"System Security"` güven veriyor ama domain
  `updatecenter.com`  hedeflenen kurumla hiçbir ilgisi yok.

> **📌 Aşamanın en önemli dersi:** Bu örnekte **SPF pass** ve **Return-Path = From**.
> İki "kolay" sinyal de temiz. Phishing'i ele veren şey header'daki **`gophish` izi +
> VPS kaynak IP + DKIM/DMARC yokluğu + gövdedeki tracking pixel + credential link +
> yazım hatası.** Gerçek analiz, tek bir alana değil **sinyallerin toplamına** bakar.

### 6.4 Gövde (body)  sosyal mühendislik + teknik IOC

```html
<p>Dear Employees,</p>
<p>...connection problems... check your access via the link below:</p>
<a href="https://updatecenter.com?rid=xHn2EWg">ACCESS CONTROL</a>
<p>Provide your information...</p>
<p>System Adminsitrator Group</p>
<img alt='' style='display: none' src='https://updatecenter.com/track?rid=xHn2EWg'/>
```

| Bulgu | Yorum |
|-------|-------|
| **Credential link** | `hxxps://updatecenter[.]com?rid=xHn2EWg` ("ACCESS CONTROL")  bilgi toplama sayfası |
| **Tracking pixel** | `<img style='display:none' src='.../track?rid=xHn2EWg'>`  görünmez 1×1 izleyici. E-posta **açılınca** saldırgana "adres canlı + açılma zamanı" sinyali gider. `rid` = kampanyada kurbanı eşleyen kimlik |
| **Jenerik hitap + aciliyet** | "Dear Employees" + "connection problems" + "Provide your information" → baskı + bilgi talebi |
| **Yazım hatası** | "System Adminsi**tra**tor" (Administrator yanlış) → düşük-kalite phishing işareti |

### 6.5 Çıkarılan IOC'ler

| Tür | Değer (defanged) |
|-----|------------------|
| Gönderen adres | `administrator@updatecenter[.]com` |
| Phishing domain | `updatecenter[.]com` |
| Kaynak IP (VPS) | `165.22.86[.]103` (DigitalOcean) |
| Relay IP | `173.201.193[.]231` (GoDaddy / secureserver.net) |
| Credential URL | `hxxps://updatecenter[.]com?rid=xHn2EWg` |
| Tracking URL | `hxxps://updatecenter[.]com/track?rid=xHn2EWg` |
| Konu | `Important Update in E-Mail Systems` |
| Araç | GoPhish (`X-Mailer: gophish`) |

### 6.6 Karar ve aksiyon

- **Karar: TP  credential harvesting phishing (GoPhish kampanyası).**
- **Aksiyon:**
  1. Mail gateway'de `updatecenter.com` ve gönderen adresini **blokla**.
  2. Proxy/firewall'da domain + IP'leri (`165.22.86.103`, `updatecenter.com`) **engelle**.
  3. **Kampanya kapsamı:** aynı konu/gönderenden kaç kullanıcıya gitti? Tıklayan /
     bilgi giren var mı? (Varsa → parola sıfırlama + oturum iptali.)
  4. IOC'leri Threat Intel'e besle (**Aşama 13**).
  5. Kısa olay raporu (özet + kanıt + IOC tablosu + aksiyon).

---

## 7. Hızlı triyaj akışı (checklist)

```text
1. .eml'i METİN olarak aç (tıklama yok)
2. Received zinciri (alttan üste) → gerçek kaynak IP + makine adı
3. Authentication-Results → SPF / DKIM / DMARC (pass'e KANMA)
4. From vs Return-Path vs Reply-To → uyuşmazlık?
5. Display name vs gerçek domain → hile?
6. Gövde: linkleri defang et → typosquat / görünen-metin ≠ href / tracking pixel
7. Ekler: açma → uzantı + SHA-256 → Threat Intel
8. IOC listesi çıkar → TP/FP kararı → blokla + raporla
```

---
## Beceriler (bu aşamada kanıtlanan)

`E-posta header analizi` · `Received zinciri okuma` · `SPF/DKIM/DMARC yorumu` ·
`URL defang & typosquat tespiti` · `Tracking pixel farkındalığı` · `IOC çıkarma` ·
`TP/FP triyaj kararı` · `Credential harvesting tanıma`

> **Numune kaynağı:** `actionrequired.eml`, bir Junior SOC Analyst sertifikasyon
> lab'ının "Email Investigation" modülünden alınmış, eğitim amaçlı zararsız bir
> GoPhish simülasyonudur. İçindeki `updatecenter.com` ve IP'ler lab senaryosuna aittir.
