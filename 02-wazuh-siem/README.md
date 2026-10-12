# Aşama 2 — Wazuh SIEM

> ✅ Tamamlandı.

## SIEM nedir? Wazuh nedir?

**SIEM (Security Information and Event Management)**, bir ağdaki tüm cihazlardan
(sunucu, istemci, firewall...) **logları toplayan**, bunları **normalleştirip
ilişkilendiren (correlation)** ve **tehdit tespit ettiğinde alarm üreten** merkezi
sistemdir. SOC analistinin günlük çalıştığı ana ekran SIEM'dir.

**Wazuh**, açık kaynaklı, ücretsiz bir SIEM + XDR platformudur. OSSEC'ten türemiştir.
Üç ana parçadan oluşur:
- **Wazuh Manager** — logları işleyen, kurallara göre alarm üreten beyin.
- **Wazuh Indexer** (OpenSearch) — logların arandığı/saklandığı veritabanı.
- **Wazuh Dashboard** — görsel arayüz (Threat Hunting, alarmlar, ajan yönetimi).

Uç noktalara (DC, Win10) kurulan **ajan (agent)**, logları toplayıp Manager'a gönderir.

## Anahtar terimler (sözlük)

| Terim | Anlamı |
|-------|--------|
| **Agent** | Uç noktada çalışan, log toplayıp gönderen küçük yazılım |
| **Manager** | Logları kurallarla değerlendirip alarm üreten sunucu |
| **Decoder** | Ham logu alanlara ayıran (parse) bileşen (örn. `windows_eventchannel`) |
| **Rule** | "Şu koşul olursa şu seviyede alarm" tanımı |
| **Rule level** | 0 (sessiz) – 15 (kritik) arası önem derecesi |
| **ossec.conf** | Ajan/manager yapılandırma dosyası |
| **local_rules.xml** | Kendi yazdığın özel kuralların dosyası |
| **DQL** | Dashboard'da arama dili (Discover/Threat Hunting) |

## Ne yaptık (adımlar)

1. **Wazuh 4.14** sunucusunu kurduk: **192.168.1.95**.
2. Dashboard'a girdik, **Threat Hunting → Events** ekranını tanıdık.
3. **Ajanları kurduk:** DC01 ve LABPC1 üzerine Wazuh agent yükleyip Manager'a kaydettik
   (enrollment).
4. Sunucuya **SSH anahtarıyla** erişim kurduk (`~/.ssh/wazuh_lab_key`) — kural
   dosyalarını parola girmeden düzenlemek için.

## Karşılaşılan sorunlar ve çözümleri

- **Ajan yanlış isimle kaydoldu (DC01 yerine "SD2"):** Ajan eski kaydını (enrollment)
  koruyordu. Çözüm: ajanda `client.keys` silinip servis yeniden başlatıldı → doğru isimle
  tekrar kaydoldu.
- **DQL sözdizimi hatası:** `rule.level:>=10` → `DQLSyntaxError`. Doğrusu: `rule.level >= 10`
  (boşluklu, iki nokta yok). Tam eşleşmede iki nokta olur: `rule.id:100100`.
- **VM konsolunda pano (clipboard) çalışmıyor:** VMware'de kopyala-yapıştır için
  `VM → Settings → Options → Guest Isolation → Enable copy and paste`.

## Güvenli çalışma yöntemi (bu labın altın kuralı)

Wazuh kural dosyalarını düzenlerken **Python script** kullandık (sed/bash tırnak
sorunları yaşatıyordu). İş akışı:
1. Script host'ta yazılır → `scp` ile sunucuya gönderilir.
2. Kullanıcı `sudo bash /home/melih/<script>.sh` ile çalıştırır (parolayı kendisi girer).
3. Script kuralı ekler + `systemctl restart wazuh-manager` yapar.

## SOC / mavi takım gözüyle

- **Rule level mantığı:** 0 = log'la ama alarm verme (gürültü bastırma); 12+ = kritik,
  e-posta bildirimi eşiği. Doğru seviyelendirme, analisti alarm selinde boğulmaktan kurtarır.
- **Threat Hunting**, olayları DQL ile aramanın yeridir — ama dikkat: burada sadece
  **alarm üretmiş** (level ≥ 1) olaylar görünür. Level 0 olaylar indekslenmez.

---

## 🎓 Mülakat / sınav notları

- **SIEM ne işe yarar?** → Dağınık logları merkezileştirir, ilişkilendirir, tespit +
  uyarı + araştırma + uyumluluk (compliance) sağlar.
- **Agent-based vs agentless log toplama?** → Ajanlı: zengin veri, gerçek zamanlı, yük
  uç noktada. Ajansız (syslog/WMI): kurulum kolay ama sınırlı.
- **Bir kural neden tetiklenmez?** → Zinciri kontrol et: üretim → iletim (ajan) → ulaşım
  (manager) → eşleşme (doğru kural ağacı). (Bunu Aşama 6'da birebir yaşadık.)
- **False positive neden kötü?** → Analist körelir (alert fatigue), gerçek tehdidi kaçırır.
