# Koschei Web3 Hub — Actor Investigation Engine

**Ruleset & mimari referansı — v1.0**  
**Statü:** Aktif actor-intelligence alt sistemi pusulası. Actor/token işleri bu dokümandaki filtreden geçer.  
**Konum:** Repo kökü. Actor/token görevleri bu dokümana; ürün-geneli savunma doğrulama görevleri `WEB3_DEFENSE_VALIDATION_ENGINE.md` belgesine referans verir.

---

## 0. Tek cümlelik ürün tanımı

Koschei Actor Investigation Engine bir risk kartı üreticisi değildir. Bir araştırmacının saatlerce Solscan gezerek bulacağı aktör bağlantılarını dakikalar içinde, işlem imzalarıyla kanıtlanmış şekilde ortaya çıkaran **wallet-first + token-first actor investigation** alt sistemidir.

Skor hikâyeyi oluşturmaz. **Kanıtlar verdict'i doğurur.** Verdict, zincirin ilk çıktısı değil, son çıktısıdır.

Koschei Web3'ün ürün-geneli sorusu artık “Web3 savunmalarını kim sınayacak?”tır. Bu alt sistem, gerçek olay ve aktör örüntülerini savunma senaryolarına kanıt olarak sağlayabilir; test edilen bir güvenlik kontrolü için `VALIDATED / FAILED / INCOMPLETE` sonucu üretemez veya değiştiremez. Ürün-geneli sözleşme: [`WEB3_DEFENSE_VALIDATION_ENGINE.md`](./WEB3_DEFENSE_VALIDATION_ENGINE.md).

---

## 1. On soru filtresi

Actor/token investigation kapsamındaki bu sorulara cevap vermeyen tarama boştur. Bu alt sistem için yeni bir özellik fikri geldiğinde tek test şudur: **Bu iş aşağıdaki sorulardan en az birine cevap veriyor mu? Vermiyorsa actor roadmap'inden kesilir.** Savunma-doğrulama çalışmaları kendi canonical filtresine tabidir.

1. Token'ı kim oluşturdu?
2. Creator ilk SOL'u nereden aldı?
3. Aynı creator başka hangi token'ları çıkardı?
4. İlk token dağıtımı hangi cüzdanlara gitti?
5. Bu cüzdanlar daha sonra top holder oldu mu?
6. Aynı baskın holder başka token'larda tekrar göründü mü?
7. Creator ile holder arasında doğrudan transfer/funding imzası var mı?
8. Likiditeyi kim ekledi, kim kaldırdı?
9. Aynı funding source / deployer / holder / recipient ağı kaç projede tekrarlandı?
10. Hangi iddia doğrulanmış, hangisi yalnızca şüphe, hangisi henüz bilinmiyor?

---

## 2. Pipeline

Kullanıcı ister mint, ister wallet, ister transaction girsin — hepsi aynı actor graph'e bağlanır:

```text
Wallet / Mint / Transaction
        ↓
Target classification
        ↓
Creator & funding origin
        ↓
Created tokens
        ↓
Initial distribution
        ↓
Top holders + beneficial owner aggregation
        ↓
Creator ↔ holder transfers
        ↓
Liquidity add/remove activity
        ↓
Cross-token repeat actors
        ↓
Signed evidence graph
        ↓
Narrative + final risk verdict
```

**Maliyet notu:** En pahalı adımlar `Initial distribution` ve `Top holders aggregation` adımlarıdır. Bu adımlarda recipient/holder başına **full wallet history ASLA sorgulanmaz**. Yalnızca ilgili mint'in ATA'sı sorgulanır; yani mint-spesifik ATA sorgusu yapılır. Bu, RPC signature window probleminin kalıcı çözümüdür ve pipeline'ın ön koşuludur.

---

## 3. Dört kanıt seviyesi

Her ilişki açıkça sınıflandırılır:

| Seviye | Tanım | Verdict/grade etkisi |
|---|---|---|
| **VERIFIED** | İşlem imzası veya doğrulanmış hesap ilişkisi var | Hard trigger olabilir |
| **OBSERVED** | Aynı adres farklı taramalarda gerçekten görüldü | Compounding rule'a girer |
| **INFERRED** | Birden fazla kanıttan çıkarım; doğrudan transfer yok | Grade'i ASLA tek başına düşürmez; yalnızca `watch flag` |
| **UNVERIFIED** | Henüz doğrulanmadı | Raporda iddia olarak kullanılmaz; grade'e girmez |

Sistem “bu adam dolandırıcı” demez. Şunu der:

> Aynı creator iki token'da doğrulandı. Aynı dominant holder iki token'da tekrar gözlendi. Creator-to-holder doğrudan funding ilişkisi henüz doğrulanmadı.

**Graceful degradation:** `Veri yok`, `doğrulanmadı` ve `araştırılmadı` üç ayrı durumdur; UNVERIFIED içinde karıştırılmaz. Funding izi CEX hot wallet'ta bitiyorsa rapor boş bırakmaz ve açıkça şunu yazar:

```text
Trail ends at CEX (HTX) — identity opaque
```

---

## 4. Kanıt satırı standardı

Her ciddi iddianın yanında şu alanlar zorunludur:

- `signature`
- `slot`
- `timestamp`
- `source wallet`
- `destination wallet`
- `amount`
- `program`
- `verification status` (`VERIFIED / OBSERVED / INFERRED / UNVERIFIED`)

Kanıt satırı olmayan iddia rapora girmez.

---

## 5. Verdict: kural tabanlı, sayısız, versiyonlu

Ağırlıklı skor formülü YOK. Sayısal skor (`95/100`) YOK. Yalnızca **harf notu + tetikleyen kural listesi** vardır.

### Kademe 1 — Hard triggers

Herhangi biri VERIFIED ise verdict tavanı sabitlenir. Diğer kanıtlar yalnızca bağlamı güçlendirir.

| Kural | Tavan |
|---|---|
| Liquidity removal by creator (`VERIFIED`) | En iyi ihtimalle **D** |
| Direct creator → dominant-holder funding (`VERIFIED`) | En iyi ihtimalle **D** |
| Creator'ın önceki token'ında rug/removal geçmişi (`VERIFIED`) | En iyi ihtimalle **C** |

### Kademe 2 — Compounding rules

Tek başına masum olabilecek sinyaller, iki veya daha fazla açık kural birleşince bir kademe düşürür:

- Creator reused across tokens (`VERIFIED`) + dominant holder reused (`OBSERVED`)
- CEX-opaque funding + fresh wallet holders (`<30 gün`) + konsantrasyon eşiği

Compounding, ağırlıklı toplamla değil **farklı tetiklenmiş kural kimlikleriyle** çalışır.

### Kademe 3 — INFERRED ve UNVERIFIED

- `INFERRED` asla tek başına grade düşürmez; raporda yalnızca **watch flag** olarak görünür.
- `UNVERIFIED` grade'e hiç girmez ve raporda doğrulanmış iddia gibi kullanılmaz.

### Çıktı formatı

Yanlış:

```text
CRITICAL 95/100
→ birkaç genel cümle
```

Doğru:

```text
Creator reused across multiple tokens (VERIFIED)
Same dominant holder reappeared (OBSERVED ×2)
Liquidity removal observed (VERIFIED, sig: 4Ujsd...)
Direct transfer relation: NOT VERIFIED
→ Verdict: D — triggered by rules [R-03, R-07, R-11] — ruleset v1.0
```

Her verdict'in altında `ruleset vX.Y` yer alır. “Geçen hafta C'ydi, neden şimdi D?” sorusunun cevabı deterministiktir. İmzalı verdict yalnızca deterministik kurallarla anlamlıdır.

### AI'nin rolü

Grade'i AI üretmez — kurallar üretir. AI yalnızca **narrative katmanında** tetiklenen kuralları insan diline çevirir.

Doğru ifade:

> Kurallar D verdi, AI anlattı.

Yanlış ifade:

> Claude token'a D verdi.

---

## 6. Actor index — kalıcı hafıza

`Cross-token repeat actors` adımı yalnızca tarama anında hesaplanamaz; kalıcı bir indeks gerektirir:

```text
adres → (rol, mint, evidence, timestamp)
```

- İlk sürüm yalnızca Koschei'nin kendi tarama geçmişinden beslenir. Bu yeterlidir ve zamanla değerlenen bir moat oluşturur.
- **30 günlük retention worker actor index tablosunu SİLMEZ.**
- Retention yalnızca ham tarama verisine uygulanır; actor index kalıcıdır.
- Mevcut structural memory cache bu indeksin embriyosudur ve ayrı tablo olarak genişletilir.

---

## 7. Referans rapor: `yHCx...6PRe` vakası

Bu cüzdan ilk canlı kabul testidir. Koschei bu cüzdanı taradığında `risk 70` üretmez; aşağıdaki yapıda bir dosya üretir.

### Actor profile

- Wallet: `yHCx...6PRe`
- Observed role: token creator / operator
- Initial funding source: HTX Hot Wallet (`84d önce`) — `Trail ends at CEX, identity opaque`
- Observation scope: verified on-chain history

### Created-token history

- ANSEM / The Black Bull (`9cRCn9...TGpump`, `26d`)
- Cult of Z (`6QPvGr...JJonYM`, aynı creator, yaklaşık 25 gün sonra)
- Diğer doğrulanan mintler

Her token için şu alanlar çıkarılır:

- mint
- creation signature
- creation time
- creator relationship
- initial buyers
- initial recipients
- liquidity pair
- liquidity provider
- liquidity removal events
- top holders
- repeat actors

### Cross-token bağlantılar

- Creator reused across: `2+ tokens` (`VERIFIED`)
- Dominant holder reused across: `2 tokens` (`OBSERVED`)
- Direct creator → dominant-holder funding: `verified / not verified`
- Shared funding source: `verified / not verified`
- Shared first buyers: count
- Shared recipient wallets: count

### Bu vakada bilinen sinyaller — 2026-07-13 gözlem seti

- Creator cüzdanında Z launch'ından saatler sonra `BURN -1,000,000` + `CLOSE ACCOUNT` (`VERIFIED`, sig: `4Ujsd...`)
- İki yaklaşık `$3M` ANSEM holder'ı (`CLM6E4...`, `2xmDGY...` / `cryptowhizz.sol`) aynı dust kaynaklarından besleniyor (`4ZPAaiA4HK...`, `7otjQQExWb...`) — `OBSERVED`
- Funding yaş asimetrisi: `243 gün` ve `11 gün`
- Creator'a onlarca cüzdandan sürekli tek yönlü token girişi — konsolidasyon pattern'i

Bu maddeler, tam signature/evidence satırı mevcut değilse yalnızca kabul testi beklentisi veya gözlem olarak kalır; doğrulanmış rapor iddiasına dönüşmez.

---

## 8. İlk sürüm kabul kriterleri

1. `yHCx...6PRe` doğrudan owner paneline girilebilecek.
2. Cüzdan türü doğru tanınacak.
3. Oluşturduğu mintler listelenecek.
4. İlk funding kaynağı gösterilecek; CEX'te bitiyorsa açıkça belirtilecek.
5. Token çıkışları ve recipient cüzdanlar çıkarılacak.
6. Recipient'lar top holder listeleriyle eşleştirilecek.
7. Likidite ekleme/kaldırma olayları imzalarıyla gösterilecek.
8. Aynı creator ve holder'ın diğer token tekrarları bulunacak.
9. Direct creator → holder ilişkisi varsa kanıtlanacak; yoksa açıkça `doğrulanmadı` denecek.
10. En sonda tek bir evidence-backed verdict üretilecek.

### İlk sprint — en dar dikey kesit

```text
Tek cüzdan girişi
→ created mints
→ funding origin
→ her mint için ilk 20 recipient'ın ATA-bazlı akıbeti
```

Cross-token ve liquidity katmanları ikinci turdur. Bu kesit tek başına `yHCx` vakasının temel dosyasını üretebilir ve pazarlamada kullanılabilir.

---

## 9. Kapsam dışı

- Sayısal skor (`0–100`) — kaldırıldı, geri gelmeyecek
- Verdict-first rapor düzeni — kaldırıldı
- On soru filtresinden geçmeyen her yeni actor/token investigation özelliği — actor roadmap'inden otomatik red
- INFERRED ilişkilere dayalı suçlama dili — yasak
- Demo/beta/sentetik rapor — yasak

---

## 10. Konumlandırma notu

Actor-investigation yüzeyindeki rakip tarama araçları **nokta savunmasıdır**: token'a bakar ve o anki görüntüye skor basar. Bu Koschei alt sistemi **entegre hava resmi** çıkarır: aktörü, fırlatma geçmişini, tedarik zincirini (`funding`) ve önceki angajmanlarını tek imzalı dosyada birleştirir.

> Diğerleri füzeyi görür. Koschei fırlatma rampasını izler.

`Scan before you sign` = angajman öncesi hedef teşhisi.

---

*Bu doküman 2026-07-13/14 mimari kararlarının damıtılmış halidir. Değişiklikler ruleset versiyonuyla birlikte kaydedilir.*
