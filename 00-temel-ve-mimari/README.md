# Aşama 0 — Temel ve Mimari

Bu aşamada tek bir şeye odaklandım: her şeyin üstüne oturacağı sağlam bir zemin kurmak.
Buradaki küçük bir hatanın (örneğin yanlış DNS) ileride "domaine katılamıyorum" diye saatler
kaybettirdiğini biliyordum, o yüzden hiç acele etmedim.

---

## 1. Ağ modu: Bridged (köprü)

Bu labda **bridged** ağ kullandım. Bridge modunda her sanal makine, kendi ağ kartıyla doğrudan
**ev ağına** bağlanır ve modemden (veya elle verdiğim statik adresle) `192.168.1.0/24` ağından
bir IP alır. Yani VM'lerim, ağdaki gerçek bir fiziksel bilgisayar gibi davranır; host'tan ve
ağdaki diğer cihazlardan doğrudan erişilebilirler.

VMware'de üç temel ağ modu var:

- **Bridged:** VM gerçek ev ağına katılır, modemden IP alır. *(Bu labda bunu kullandım.)*
- **Host-only:** VM'ler sadece birbirleriyle ve host ile konuşur, internete çıkamaz.
- **NAT:** VM'ler kendi aralarında + host'un internetini paylaşarak dışarı çıkar, ama dışarıdan erişilemez.

### ⚠️ Bridge modunun iki önemli sonucu (bilerek seçtim)

1. **Saldırılar ev ağına taşar.** Aşama 6'daki LLMNR/NBT-NS zehirleme (Responder) ve ARP tabanlı
   saldırılar, bridge modunda **evdeki gerçek cihazları** da etkileyebiliyor. Bu saldırıları
   çalıştırırken ağda başka önemli cihaz olmamasına dikkat ettim; mümkün olduğunca bu aşamaları
   ağın sakin olduğu zamanlarda yaptım.
2. **FortiGate "çevre güvenlik duvarı" olarak araya giremez.** Ev modemim zaten `192.168.1.1` ağ
   geçidi rolünü tutuyor. Bu yüzden FortiGate'i bu labda inline (trafiğin önünde) bir firewall
   olarak değil, **ayrı bir log kaynağı** olarak ele aldım  ayrıntısı [Aşama 10](../10-fortigate/).

---

## 2. Statik IP neden şart

Tespit kuralları yazacaktım ve bu kurallar "192.168.1.100'den gelen tarama" gibi IP'lere dayanıyor.
IP değişirse kurallar bozulur. Bu yüzden lab makinelerime **sabit (statik) IP** verdim.

> **DHCP çakışması uyarısı:** Seçtiğim statik IP'lerin, modemin otomatik dağıttığı (DHCP) aralığın
> **dışında** olmasına dikkat ettim; yoksa iki cihaz aynı IP'yi alıp çakışır. İki güvenli yol var:
> - **a)** Modemin DHCP aralığını öğren (çoğu modemde `.100`–`.200` civarı) ve statik IP'leri bu
>   aralığın dışından seç, **veya**
> - **b)** Modem arayüzünden bu IP'ler için **DHCP reservation** (MAC'e sabit IP) tanımla.

---

## 3. IP planı (Bridge / `192.168.1.0/24`)

Lab boyunca başucu kağıdım bu tablo oldu.

| Makine | IP | Ağ geçidi | DNS | Rol |
|--------|-----|-----------|-----|-----|
| Ev modemi | 192.168.1.1 |  |  | Gerçek ağ geçidi + internet |
| Host (kendi bilgisayarım) | 192.168.1.108 | 192.168.1.1 | 192.168.1.1 | Fiziksel makine |
| Domain Controller (DC01, WS2019) | 192.168.1.75 | 192.168.1.1 | 127.0.0.1 (kendisi) | AD DS + DNS |
| Windows 10 (LABPC1) | 192.168.1.85 | 192.168.1.1 | 192.168.1.75 | Domain üyesi |
| Wazuh SIEM | 192.168.1.95 | 192.168.1.1 | 192.168.1.1 | SIEM |
| Kali | 192.168.1.105 | 192.168.1.1 | 192.168.1.1 | Saldırgan |
| FortiGate | 192.168.1.23 | 192.168.1.1 | 192.168.1.1 | Log kaynağı (Aşama 10) |

Alt ağ maskesi hepsinde `255.255.255.0`.

### En kritik DNS kuralı

Domaine katılacak Windows makinelerimin (DC ve Win10) DNS'ini **mutlaka DC'yi gösterecek** şekilde
ayarladım:

- **DC'nin DNS'i** kendisini gösterir: `127.0.0.1`. İnternete çıkabilmesi için DNS rolünde
  **forwarder** olarak `192.168.1.1` (veya `8.8.8.8`) tanımladım  bunu Aşama 1'de DC'yi kurarken yaptım.
- **Win10'un (LABPC1) DNS'i** `192.168.1.75` (DC) olmalı. DNS `192.168.1.1` kalırsa Win10 domaini
  bulamaz ve katılamaz  **yeni başlayanların 1 numaralı takıldığı yer burası, ben de dikkat ettim.**
- Wazuh ve Kali domain üyesi olmadığı için DNS'lerini doğrudan `192.168.1.1` bıraktım.

> **Geçici istisna:** DC'yi ilk kurarken henüz DNS rolü yokken, internet için DNS'ini geçici olarak
> `192.168.1.1` yaptım; DC Promosyonundan sonra `127.0.0.1`'e çevirdim.

---

## 4. Nasıl kurdum (uygulama)

**a) Her VM'i bridge'e bağladım.** Her makinede `VM → Settings → Network Adapter → Bridged:
Connected directly to the physical network` seçtim. Host'ta birden fazla ağ kartı olduğu için
(Wi-Fi + Ethernet), `Edit → Virtual Network Editor → VMnet0` altından köprülenecek **doğru fiziksel
kartı** elle seçtim (otomatik bırakınca yanlış kartı seçebiliyor).

**b) Statik IP verdim.**
- **Windows'ta:** Denetim Masası → Ağ Bağlantıları → ilgili adaptör → sağ tık Özellikler → IPv4 →
  "Aşağıdaki IP adresini kullan" → tablodaki değerleri girdim.
- **Linux'ta (Wazuh/Kali):** terminalden `sudo nmtui` çalıştırıp menüden statik IP girdim.
  (Detayını Aşama 2'de Wazuh'u kurarken adım adım gösteriyorum.)

**c) Bağlantıyı doğruladım.** Makineleri açıp birbirlerini ping'ledim:
- Win10'dan `ping 192.168.1.75` (DC) ve `ping 8.8.8.8` (internet).
- İkisi de cevap verince ağın hazır olduğunu anladım.
- (Windows güvenlik duvarı ICMP'ye cevap vermeyebiliyor; gelen ICMP'yi geçici açmam gerekti 
  "File and Printer Sharing (Echo Request - ICMPv4-In)".)

**d) Temiz snapshot aldım.** Her makineyi kurup IP'sini ayarladıktan, ama henüz hiçbir şeyi
bozmadan önce snapshot aldım: `VM → Snapshot → Take Snapshot`, adını `temiz-kurulum` koydum. Bu
benim geri dönüş noktam oldu.

> **Altın kuralım:** Her saldırı aşamasından **önce** ilgili makinelerin snapshot'ını aldım.
> Mimikatz'la sistemi bozduğumda ya da yanlış bir GPO ile domaini kilitlediğimde tek tıkla temiz
> haline dönebildim.

---

## 5. Kaynak planı (32 GB RAM)

| Makine | RAM | CPU | Not |
|--------|-----|-----|-----|
| Host (kendi OS'um) | 6–8 GB |  | Buna dokunmadım |
| FortiGate | 2 GB | 1 | Hafif |
| Domain Controller | 4 GB | 2 | AD + DNS |
| Windows 10 | 4 GB | 2 | İstemci |
| Wazuh | 6 GB | 2 | En aç makine, logları o işliyor |
| Kali | 4 GB | 2 | Sadece saldırırken açık tuttum |

İlk disiplinim: **ihtiyacım olmayan makineyi kapatmak.** Kali'yi sadece saldırı aşamalarında açtım.

---

## Bu aşamada tamamladıklarım

- [x] Tüm VM'ler bridge'e bağlı
- [x] Statik IP'ler verildi (DHCP çakışması kontrol edildi)
- [x] Ping testleri başarılı (iç ağ + internet)
- [x] Her makinede `temiz-kurulum` snapshot'ı alındı
- [x] Topoloji diyagramı `gorseller/topoloji.png` olarak eklendi
