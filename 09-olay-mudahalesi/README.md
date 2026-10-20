# Aşama 9 — Olay Müdahalesi (Incident Response)

> ✅ Tamamlandı  labda ürettiğim uçtan uca saldırı zincirini bir SOC vaka raporuna döktüm:
> **[vaka-raporu.md](vaka-raporu.md)** (IR-2026-001).

## Incident Response (IR) nedir?

**Olay müdahalesi (IR)**, bir güvenlik olayı tespit edildikten sonra uygulanan **yapılandırılmış
süreç**: olayı anlamak, yayılmasını durdurmak, temizlemek, normale dönmek ve dersleri çıkarmak. Bir
SOC analistinin **gerçek işinin** büyük ölçüde bu olduğunu düşünüyorum alarm düştükten sonrası.

## Standart IR yaşam döngüsü (SANS / NIST)

| Adım | Ne yapılır |
|------|-----------|
| **1. Preparation (Hazırlık)** | Araçlar, loglar, playbook'lar, yetkiler hazır mı |
| **2. Identification (Tespit)** | Olay gerçek mi? Kapsamı ne? (triyaj) |
| **3. Containment (Kapsama)** | Yayılmayı durdur (makineyi izole et, hesabı kilitle) |
| **4. Eradication (Temizleme)** | Kök nedeni kaldır (zararlı, backdoor, çalınan kimlik) |
| **5. Recovery (Kurtarma)** | Sistemleri güvenli şekilde geri al, izle |
| **6. Lessons Learned (Dersler)** | Rapor yaz, tespiti/savunmayı iyileştir |

## Anahtar terimler

| Terim | Anlamı |
|-------|--------|
| **Triage** | Alarmın gerçek/öncelikli olup olmadığını hızlı değerlendirme |
| **Timeline** | Olayın zaman çizelgesi (ne, ne zaman, hangi sırayla) |
| **IOC** | Indicator of Compromise uzlaşma göstergesi (IP, hash, domain) |
| **Containment** | Zararı sınırlama |
| **Root cause** | Kök neden |
| **Playbook** | Belirli bir olay türü için adım adım müdahale rehberi |

## Ne yaptım

Bu labda ürettiğim **gerçek saldırı zincirini** baştan sona bir **vaka raporu (IR writeup)** olarak
yazdım → **[vaka-raporu.md](vaka-raporu.md)**. Zincir:
```
Brute-force → Kerberoasting → Credential dumping → Lateral movement (PsExec)
```
Rapora şunları koydum:
1. **Yönetici özeti** + saldırı zinciri görseli
2. **Timeline** (hangi evre, hangi kaynak/hedef, hangi kural, hangi log)
3. **Tespit & analiz** (evre evre)
4. **Containment → Eradication → Recovery** adımları
5. **IOC listesi** + **MITRE ATT&CK eşlemesi**
6. **Kök neden + somut öneriler** (hangi öneri hangi evreyi kırar)

## SOC / mavi takım gözüyle

- IR'de **hız ve disiplinin** her şey olduğunu öğrendim: panikle değil, playbook'la hareket ederim.
- **Containment önce, analiz sonra** olabiliyor  yayılan bir saldırıda önce kanamayı durdururum.
  Ama kanıtı (forensics) bozmamaya dikkat ederim.
- İyi bir IR raporunun, aynı olayın **tekrar yaşanmaması** için somut öneriler içermesi gerektiğini
  biliyorum.

---
