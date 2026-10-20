# Aşama 8 — MITRE ATT&CK ve Detection Engineering

> ✅ Tamamlandı 

## MITRE ATT&CK nedir?

**MITRE ATT&CK**, gerçek dünyadaki saldırganların kullandığı **taktik ve teknikleri** kataloglayan,
ücretsiz ve küresel bir **bilgi tabanı**. Saldırıları ortak bir dile döküyor: "saldırgan ne yapmaya
çalışıyor (taktik) ve bunu nasıl yapıyor (teknik)".

Yapısı:
- **Tactic (Taktik):** Saldırganın amacı  örn. *Credential Access* (kimlik ele geçirme).
- **Technique (Teknik):** Amaca ulaşma yolu  örn. *T1558.003 Kerberoasting*.
- **Sub-technique:** Tekniğin alt kırılımı (`.003` gibi).

Neden önemli? Çünkü SOC'un işi "hangi saldırıyı yakalayabiliyorum, hangisini yakalayamıyorum?"
sorusunu yanıtlamak. ATT&CK bana bunu **haritalama** imkânı veriyor.

## Anahtar terimler

| Terim | Anlamı |
|-------|--------|
| **Tactic / Technique / Sub-technique** | Amaç / yöntem / alt yöntem |
| **Detection coverage** | Hangi tekniklerin tespit kapsamında olduğu |
| **Gap (boşluk)** | Tespit edilemeyen teknikler |
| **ATT&CK Navigator** | Kapsamı renkli ısı haritasında gösteren araç |
| **Detection engineering** | Saldırı tekniğini tespit kuralına çevirme disiplini |

## Labda ürettiğim ve eşlediğim teknikler (teknik → tespit kuralı)

| Teknik | Taktik | Aşama | Tespit | Tip |
|--------|--------|-------|--------|-----|
| **T1110** Brute Force | Credential Access | 05 | ✅ rule 100100 (lvl 10) | Davranış (özel) |
| **T1558.003** Kerberoasting | Credential Access | 06 | ✅ rule 100300 (lvl 12) | Teknik/davranış (özel) |
| **T1003.001** LSASS Memory | Credential Access | 07 | ✅ rule 100310 + 100320 | İmza + davranış (özel) |
| **T1021.002** SMB/Admin Shares | Lateral Movement | 07 | ✅ rule 92650 (lvl 12) | Hazır ruleset |
| **T1570** Lateral Tool Transfer | Lateral Movement | 07 | ✅ hazır ruleset | Hazır ruleset |
| **T1569.002** Service Execution | Execution | 07 | ✅ rule 92307 / 7045 | Hazır ruleset |
| **T1550.002** Pass-the-Hash | Lateral Movement | 07 | ⚠️ rule 92652 (kısmi) | Hazır (kısmi) |
| **T1562.001** Impair Defenses | Defense Evasion | 07 | ⚠️ izlenebilir (kuralsız) → Aşama 20'de kapattım | Boşluk → kapandı |

**Kapsam durumu (o anki fotoğraf):** Credential Access taktiğinde çok güçlüydüm (3 teknik tam
tespit), Lateral Movement iyiydi, ama **Reconnaissance, Persistence, Command & Control,
Exfiltration, Impact** taktiklerinde henüz **boşluğum** vardı. Navigator haritası bunu net
gösteriyordu  ve sonraki aşamalarda (14–20) bu boşlukların çoğunu bilerek kapattım.

## Navigator kapsam haritası nasıl açılır?

`soc-ev-lab-navigator-layer.json` dosyasını bu klasöre koydum. Açmak için:

1. Tarayıcıda **https://mitre-attack.github.io/attack-navigator/** adresine git.
2. **"Open Existing Layer"** → **"Upload from local"** seç.
3. `soc-ev-lab-navigator-layer.json` dosyasını yükle.
4. Enterprise matris, yakaladığım teknikler **yeşil** (tam tespit) ve **sarı** (kısmi) olarak
   işaretlenmiş şekilde açılır. Her hücreye tıklayınca hangi kuralın yakaladığı (comment alanında)
   görünür.

> İnternetsiz çalışmak istersen Navigator'ı yerel de çalıştırabilirsin, ama online sürüm en
> pratiği (dosya tarayıcıda işlenir, dışarı veri gitmez).

## SOC / mavi takım gözüyle

- ATT&CK haritasının, bir SOC'un **olgunluğunu** gösteren en somut belge olduğunu düşünüyorum.
  İşverene "şu teknikleri yakalıyorum, şu boşluklarım var ve planım bu" diyebilmek çok değerli.
- Her yeni tespit kuralım, haritada bir hücreyi yeşile çeviriyor  bu benim için somut ilerleme kanıtı.
- **Boşluk analizi (gap analysis):** Haritadaki renksiz taktikler (o an C2, Exfiltration,
  Persistence) bir sonraki tespit çalışmamın yol haritası oldu.

