# Aşama 0 — Temel ve Mimari

Bu aşamanın tek amacı: her şeyin üstüne oturacağı sağlam bir zemin kurmak.
Buradaki küçük bir hata (örneğin yanlış DNS) ileride "domaine katılamıyorum"
diye saatler kaybettirir. Acele etme.

---

## 1. Ağ modu: Bridged (köprü)

Bu labda **bridged** ağ kullanıyoruz. Bridge modunda her sanal makine, kendi
ağ kartıyla doğrudan **ev ağına** bağlanır ve modeminden (veya elle verdiğimiz
statik adresle) `192.168.1.0/24` ağından bir IP alır. Yani VM'ler, ağdaki
gerçek bir fiziksel bilgisayar gibi davranır; host'tan ve ağdaki diğer
cihazlardan doğrudan erişilebilirler.

VMware'de üç temel ağ modu vardır:

- **Bridged:** VM gerçek ev ağına katılır, modemden IP alır. *(Bu labda bunu kullanıyoruz.)*
- **Host-only:** VM'ler sadece birbirleriyle ve host ile konuşur, internete çıkamaz.
- **NAT:** VM'ler kendi aralarında + host'un internetini paylaşarak dışarı çıkar, ama dışarıdan erişilemez.

### ⚠️ Bridge modunun iki önemli sonucu (bilerek seçildi)

1. **Saldırılar ev ağına taşar.** Aşama 6'daki LLMNR/NBT-NS zehirleme (Responder)
   ve ARP tabanlı saldırılar, bridge modunda **evdeki gerçek cihazları** da
   etkileyebilir. Bu saldırıları çalıştırırken ağda başka önemli cihaz
   bulunmamasına dikkat et; mümkünse bu aşamaları ağın sakin olduğu bir zamanda yap.
2. **FortiGate "çevre güvenlik duvarı" olarak araya giremez.** Ev modemi zaten
   `192.168.1.1` ağ geçidi rolünü tutuyor. Bu yüzden FortiGate bu labda inline
   (trafiğin önünde) bir firewall değil, **ayrı bir log kaynağı** olarak ele
   alınır — ayrıntısı [Aşama 10](../10-fortigate/).

---

## 2. Statik IP neden şart

Tespit kuralları yazacağız ve bu kurallar "192.168.1.100'den gelen tarama" gibi
IP'lere dayanır. IP değişirse kurallar bozulur. Bu yüzden lab makinelerine
**sabit (statik) IP** veriyoruz.

> **DHCP çakışması uyarısı:** Seçtiğimiz statik IP'ler, modeminin otomatik
> dağıttığı (DHCP) aralığın **dışında** olmalı; yoksa iki cihaz aynı IP'yi
> alıp çakışır. İki güvenli yol var:
> - **a)** Modemin DHCP aralığını öğren (çoğu modemde `.100`–`.200` civarıdır) ve
>   statik IP'leri bu aralığın dışından seç, **veya**
> - **b)** Modem arayüzünden bu IP'ler için **DHCP reservation** (MAC'e sabit IP) tanımla.

---

## 3. IP planı (Bridge / `192.168.1.0/24`)

Lab boyunca başucu kağıdın bu tablo olacak.

| Makine | IP | Ağ geçidi | DNS | Rol |
|--------|-----|-----------|-----|-----|
| Ev modemi | 192.168.1.1 | — | — | Gerçek ağ geçidi + internet |
| Host (kendi bilgisayarın) | 192.168.1.108 | 192.168.1.1 | 192.168.1.1 | Fiziksel makine |
| Domain Controller (DC01, WS2019) | 192.168.1.75 | 192.168.1.1 | 127.0.0.1 (kendisi) | AD DS + DNS |
| Windows 10 (LABPC1) | 192.168.1.85 | 192.168.1.1 | 192.168.1.75 | Domain üyesi |
| Wazuh SIEM | 192.168.1.95 | 192.168.1.1 | 192.168.1.1 | SIEM |
| Kali | 192.168.1.105 | 192.168.1.1 | 192.168.1.1 | Saldırgan |
| FortiGate | 192.168.1.23 | 192.168.1.1 | 192.168.1.1 | Log kaynağı (Aşama 10) |

Alt ağ maskesi hepsinde `255.255.255.0`.

### En kritik DNS kuralı

Domaine katılacak Windows makinelerinin (DC ve Win10) DNS'i **mutlaka DC'yi
göstermeli**:

- **DC'nin DNS'i** kendisini gösterir: `127.0.0.1`. İnternete çıkabilmesi için
  DNS rolünde **forwarder** olarak `192.168.1.1` (veya `8.8.8.8`) tanımlanır —
  bunu Aşama 1'de DC'yi kurarken yapacağız.
- **Win10'un (LABPC1) DNS'i** `192.168.1.75` (DC) olmalı. DNS `192.168.1.1` kalırsa
  Win10 domaini bulamaz ve katılamaz — **yeni başlayanların 1 numaralı takıldığı yer budur.**
- Wazuh ve Kali domain üyesi olmadığı için DNS'leri doğrudan `192.168.1.1` olabilir.

> **Geçici istisna:** DC'yi ilk kurarken henüz DNS rolü yokken, internet için
> DNS'ini geçici olarak `192.168.1.1` yap; DC Promosyonundan sonra `127.0.0.1`'e çevir.

---

## 4. Yapılacaklar (uygulama)

**a) Her VM'i bridge'e bağla.** Her makinede `VM → Settings → Network Adapter →
Bridged: Connected directly to the physical network` seç. Host'ta birden fazla
ağ kartı varsa (Wi-Fi + Ethernet), `Edit → Virtual Network Editor → VMnet0`
altından köprülenecek **doğru fiziksel kartı** elle seç (otomatik bırakma,
yanlış kartı seçebilir).

**b) Statik IP ver.**
- **Windows'ta:** Denetim Masası → Ağ Bağlantıları → ilgili adaptör → sağ tık
  Özellikler → IPv4 → "Aşağıdaki IP adresini kullan" → tablodaki değerleri gir.
- **Linux'ta (Wazuh/Kali):** terminalden `sudo nmtui` çalıştırıp menüden statik
  IP gir. (Detayını Aşama 2'de Wazuh'u kurarken adım adım göstereceğiz.)

**c) Bağlantıyı doğrula.** Makineleri açıp birbirlerini ping'le:
- Win10'dan `ping 192.168.1.10` (DC) ve `ping 8.8.8.8` (internet).
- İkisi de cevap veriyorsa ağ hazır.
- (Windows güvenlik duvarı ICMP'ye cevap vermeyebilir; gelen ICMP'yi geçici
  açman gerekebilir — "File and Printer Sharing (Echo Request - ICMPv4-In)".)

**d) Temiz snapshot al.** Her makine kurulup IP'si ayarlandıktan, ama henüz
hiçbir şey bozulmadan önce snapshot al: `VM → Snapshot → Take Snapshot`, adını
`temiz-kurulum` koy. Bu senin geri dönüş noktan.

> **Altın kural:** Her saldırı aşamasından **önce** ilgili makinelerin
> snapshot'ını al. Mimikatz'la sistemi bozduğunda ya da yanlış bir GPO ile
> domaini kilitlediğinde tek tıkla temiz haline dönersin.

---

## 5. Kaynak planı (32 GB RAM)

| Makine | RAM | CPU | Not |
|--------|-----|-----|-----|
| Host (kendi OS'un) | 6–8 GB | — | Buna dokunma |
| FortiGate | 2 GB | 1 | Hafif |
| Domain Controller | 4 GB | 2 | AD + DNS |
| Windows 10 | 4 GB | 2 | İstemci |
| Wazuh | 6 GB | 2 | En aç makine, logları o işler |
| Kali | 4 GB | 2 | Sadece saldırırken açık tut |

İlk disiplin: **ihtiyacın olmayan makineyi kapat.** Kali'yi sadece saldırı
aşamalarında aç.

---

## Bu aşamada senden beklenen

- [ ] Tüm VM'ler bridge'e bağlı
- [ ] Statik IP'ler verildi (DHCP çakışması kontrol edildi)
- [ ] Ping testleri başarılı (iç ağ + internet)
- [ ] Her makinede `temiz-kurulum` snapshot'ı alındı
- [ ] Topoloji diyagramı `gorseller/topoloji.png` olarak eklendi
