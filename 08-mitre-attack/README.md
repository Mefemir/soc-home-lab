# Aşama 8 — MITRE ATT&CK ve Detection Engineering

> ✅ Tamamlandı — labda üretilen teknikler ATT&CK'e eşlendi ve Navigator kapsam
> haritası (`soc-ev-lab-navigator-layer.json`) oluşturuldu.

## MITRE ATT&CK nedir?

**MITRE ATT&CK**, gerçek dünyadaki saldırganların kullandığı **taktik ve teknikleri**
kataloglayan, ücretsiz ve küresel bir **bilgi tabanıdır**. Saldırıları ortak bir dile
döker: "saldırgan ne yapmaya çalışıyor (taktik) ve bunu nasıl yapıyor (teknik)".

Yapısı:
- **Tactic (Taktik):** Saldırganın amacı — örn. *Credential Access* (kimlik ele geçirme).
- **Technique (Teknik):** Amaca ulaşma yolu — örn. *T1558.003 Kerberoasting*.
- **Sub-technique:** Tekniğin alt kırılımı (`.003` gibi).

Neden önemli? Çünkü SOC'un işi "hangi saldırıyı yakalayabiliyorum, hangisini
yakalayamıyorum?" sorusunu yanıtlamaktır. ATT&CK bunu **haritalamayı** sağlar.

## Anahtar terimler

| Terim | Anlamı |
|-------|--------|
| **Tactic / Technique / Sub-technique** | Amaç / yöntem / alt yöntem |
| **Detection coverage** | Hangi tekniklerin tespit kapsamında olduğu |
| **Gap (boşluk)** | Tespit edilemeyen teknikler |
| **ATT&CK Navigator** | Kapsamı renkli ısı haritasında gösteren araç |
| **Detection engineering** | Saldırı tekniğini tespit kuralına çevirme disiplini |

## Labda üretilen ve eşlenen teknikler (teknik → tespit kuralı)

| Teknik | Taktik | Aşama | Tespit | Tip |
|--------|--------|-------|--------|-----|
| **T1110** Brute Force | Credential Access | 05 | ✅ rule 100100 (lvl 10) | Davranış (özel) |
| **T1558.003** Kerberoasting | Credential Access | 06 | ✅ rule 100300 (lvl 12) | Teknik/davranış (özel) |
| **T1003.001** LSASS Memory | Credential Access | 07 | ✅ rule 100310 + 100320 | İmza + davranış (özel) |
| **T1021.002** SMB/Admin Shares | Lateral Movement | 07 | ✅ rule 92650 (lvl 12) | Hazır ruleset |
| **T1570** Lateral Tool Transfer | Lateral Movement | 07 | ✅ hazır ruleset | Hazır ruleset |
| **T1569.002** Service Execution | Execution | 07 | ✅ rule 92307 / 7045 | Hazır ruleset |
| **T1550.002** Pass-the-Hash | Lateral Movement | 07 | ⚠️ rule 92652 (kısmi) | Hazır (kısmi) |
| **T1562.001** Impair Defenses | Defense Evasion | 07 | ⚠️ izlenebilir (kuralsız) | Boşluk |

**Kapsam durumu:** Credential Access taktiğinde çok güçlü (3 teknik tam tespit),
Lateral Movement iyi, ama **Reconnaissance, Persistence, Command & Control,
Exfiltration, Impact** taktiklerinde henüz **boşluk** var. Navigator haritası bunu
net gösterir.

## Navigator kapsam haritası nasıl açılır?

`soc-ev-lab-navigator-layer.json` dosyası bu klasördedir. Açmak için:

1. Tarayıcıda **https://mitre-attack.github.io/attack-navigator/** adresine git.
2. **"Open Existing Layer"** → **"Upload from local"** seç.
3. `soc-ev-lab-navigator-layer.json` dosyasını yükle.
4. Enterprise matris, yakaladığımız teknikler **yeşil** (tam tespit) ve **sarı**
   (kısmi) olarak işaretlenmiş şekilde açılır. Her hücreye tıklayınca hangi kuralın
   yakaladığı (comment alanında) görünür.

> İnternetsiz çalışmak istersen Navigator'ı yerel de çalıştırabilirsin, ama online
> sürüm en pratiğidir (dosya tarayıcıda işlenir, dışarı veri gitmez).

## SOC / mavi takım gözüyle

- ATT&CK haritası, bir SOC'un **olgunluğunu** gösteren en somut belgedir. İşverene
  "şu teknikleri yakalıyorum, şu boşluklarım var ve planım bu" diyebilmek çok değerlidir.
- Her yeni tespit kuralı, haritada bir hücreyi yeşile çevirir — bu, somut ilerleme kanıtıdır.
- **Boşluk analizi (gap analysis):** Haritadaki renksiz taktikler (bizde C2,
  Exfiltration, Persistence) bir sonraki tespit çalışmasının yol haritasıdır.

## Ekran görüntüleri

> `gorseller/` klasörüne eklenecek:
- `gorseller/08-navigator-harita.png` — Navigator'da renklendirilmiş kapsam haritası
  (Credential Access sütununun yeşil olması dikkat çekicidir)

---