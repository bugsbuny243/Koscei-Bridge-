# Koschei Web3 — Defense Validation Engine

**Ürün ve ruleset referansı — v0.1**  
**Ruleset:** `koschei-defense-validation-rules-v0.1.0`  
**Statü:** Aktif ürün pusulası; üretim aktivasyonu değil  
**İlk zincir:** Solana; çekirdek sözleşme zincirden bağımsız

## 0. Üç ürünün kesin sınırı

| Ürün | Tek cümlelik görev | Sahip olmadığı yetki |
| --- | --- | --- |
| **Koschei Web3** | “Web3 savunmalarını kim sınayacak?” sorusunun kanıt üreten ürünü | Koschei Lang semantiği, Sentinel model terfisi, cüzdan saklama veya üretim işlemi gönderme |
| **Koschei Sentinel** | Güvenlik zekâsı ve model araştırması | Kanıt üretme, sonucu değiştirme, üretim hükmü verme |
| **Koschei Lang** | Ultra güvenli çalışma ve yetki altyapısı | Web3 hükmü verme veya Sentinel modelini yönetme |

Bugünkü Web3 ürünü Sentinel'e veya Koschei Lang'e çalışma zamanı bağımlılığı kurmaz. İkisi de ayrı projedir ve ayrı yatırım tezine sahiptir.

## 1. Ürün sorusu

Koschei Web3 şu soruya cevap verir:

> Belirli sürüm ve ayardaki bir Web3 güvenlik kontrolü, gerçek kanıtla yürütülen kontrollü saldırıyı kayıptan önce yakaladı mı; geç mi kaldı; tamamen mi kaçırdı; normal davranışı yanlış mı işaretledi?

Bu bir token puanlama ürünü değildir. Bir izleme sağlayıcısının, cüzdan korumasının, protokol alarmının, özel tespit kuralının veya müdahale akışının **gerçekte çalışıp çalışmadığını** sınar.

## 2. İlk pazar boşluğu

Web3 güvenlik ürünleri çoğunlukla kod denetler, işlemi simüle eder, alarm üretir veya olaya müdahale eder. Koschei Web3 bunların yerine geçmez. Bu savunmaları kontrollü saldırı ve benign kontrol vakalarıyla, bağımsız gözlem ve yeniden üretilebilir kanıtla doğrular.

İlk konum:

> Vendor-neutral, evidence-first Web3 defense validation.

İlk müşteri grupları:

- protokoller ve DAO güvenlik ekipleri;
- cüzdan ve imza-öncesi savunma geliştiricileri;
- izleme/tespit sağlayıcıları;
- denetim firmaları ve incident-response ekipleri;
- borsa ve saklama altyapısı güvenlik ekipleri.

## 3. Bir doğrulama çalışmasının bileşenleri

```text
Sürüm pinli senaryo
        ↓
Kontrollü fork / sandbox yürütmesi
        ↓
Kontrol altındaki savunma
        ↓
Bağımsız Koschei gözlem toplayıcısı
        ↓
Saldırı + benign kontrol matrisi
        ↓
Deterministik sonuç + değişmez kanıt dosyası
```

Her çalışma şu kimlikleri bağlar:

- `run_ref`;
- `scenario_ref` ve `scenario_version`;
- zincir ve yürütme modu;
- test edilen `control_ref`, adapter sürümü ve ayar hash'i;
- bağımsız collector kimliği;
- her vakanın pre-state, post-state ve yürütme hash'i;
- saldırı etkisinin oluşacağı kesin zaman/sequence sınırı;
- tamamlanmış gözlem penceresi;
- alarmın Koschei tarafından görüldüğü zaman ve ham alarm kanıtı;
- ruleset sürümü ve deterministik rapor hash'i.

Yeniden çalıştırma kimlikleri ve run-local evidence referansları rapor hash'ine girmez; onların gösterdiği SHA-256 içerik kimlikleri girer. Böylece aynı senaryo, ayar, kanıt içeriği ve ölçümler farklı run kimlikleriyle yeniden üretildiğinde aynı rapor hash'ini verir.

Bir sağlayıcının “alarm ürettim” beyanı tek başına PASS kanıtı değildir. Alarm bağımsız collector tarafından görülmeli ve ham kanıt hash'iyle bağlanmalıdır.

## 4. Vaka matrisi

Her kontrol için en az iki sınıf zorunludur:

1. **Attack case:** Etki sınırı bulunan kontrollü saldırı.
2. **Benign control:** Aynı yüzeye benzeyen fakat yetkili/normal davranış.

Yalnızca saldırı vakası çalıştırmak yeterli değildir; her şeye alarm veren bir kontrol güvenilir savunma sayılmaz. Benign kontrol olmadan sonuç `INCOMPLETE` olur.

İlk Solana senaryo aileleri:

- ayrıcalıklı yetki ele geçirme ve kötüye kullanım;
- yanıltıcı payload / imzalanan byte ile beklenen intent uyuşmazlığı;
- upgrade authority veya program deployment değişimi;
- oracle/price manipulation öncesi ve sonrası davranış;
- likidite veya treasury drain dizisi;
- şüpheli CPI / authority / signer zinciri;
- aynı yüzeylerin yetkili benign karşılıkları.

Canlı hedefe saldırı, mainnet işlem gönderimi ve yetkisiz test yasaktır.

## 5. Deterministik sonuçlar

Vaka sonuçları:

| Sonuç | Kesin anlam |
| --- | --- |
| `CAUGHT_IN_TIME` | Doğrulanmış alarm, tanımlı etki sınırından önce veya sınırda bağımsız collector'a ulaştı |
| `CAUGHT_LATE` | Alarm geldi fakat etki sınırından sonra geldi |
| `MISSED` | Doğrulanmış ve tamamlanmış gözlem penceresinde alarm yok |
| `FALSE_POSITIVE` | Benign kontrol vakası alarm üretti |
| `CLEAN` | Benign kontrol penceresi tamamlandı ve alarm yok |
| `INCOMPLETE` | Yürütme, gözlem, süre veya kanıt zinciri doğrulanamadı |

Kontrol sonucu:

- herhangi bir `CAUGHT_LATE`, `MISSED` veya `FALSE_POSITIVE` varsa `FAILED`;
- failure yok fakat herhangi bir `INCOMPLETE` veya eksik attack/benign sınıfı varsa `INCOMPLETE`;
- tüm zorunlu vakalar doğrulanmış, saldırılar zamanında yakalanmış ve benign vakalar temizse `VALIDATED`.

`VALIDATED`, ürünün veya protokolün mutlak güvenli olduğu anlamına gelmez. Yalnızca raporda hash'lenen **kontrol sürümü + ayar + senaryo sürümü + vaka matrisi + gözlem penceresi** için geçerlidir.

## 6. Ruleset v0.1

| Kural | Amaç |
| --- | --- |
| `DV-R01` | Fork/sandbox yürütme kanıtı doğrulanmamışsa sonucu eksik bırak |
| `DV-R02` | Kontrol gözlemi bağımsız ve doğrulanmış değilse sonucu eksik bırak |
| `DV-R03` | Alarm etki sınırından sonra geldiyse `CAUGHT_LATE` |
| `DV-R04` | Tamamlanmış attack penceresinde alarm yoksa `MISSED` |
| `DV-R05` | Benign vakada alarm varsa `FALSE_POSITIVE` |
| `DV-R06` | Tam attack + benign matrisi veya gözlem penceresi yoksa `INCOMPLETE` |

Ağırlıklı formül, olasılık veya `0–100` toplam güvenlik skoru yoktur. Detection time, lead time, miss ve false-positive sayıları ham ve kesin ölçümlerdir; skor değildir.

AI bu sonuçları üretemez, yükseltemez, düşüremez veya geçersiz kılamaz. Yalnızca deterministik sonucu açıklayabilir.

## 7. Kanıt ve fail-closed kuralı

`VALIDATED` için bütün zorunlu kanıtlar `VERIFIED` olmalıdır:

- sürüm pinli senaryo;
- fork/sandbox yürütme referansı;
- yürütme, pre-state ve post-state SHA-256 değerleri;
- bağımsız gözlem kaydı ve SHA-256 değeri;
- alarm varsa ham alarm referansı ve SHA-256 değeri;
- tamamlanmış gözlem penceresi;
- etki sınırı ve detection offset;
- test edilen kontrolün ayar SHA-256 değeri.

Eksik, bozuk, eşleşmeyen veya doğrulanmamış kanıt `VALIDATED` üretemez. Koschei üretim çıktısı uydurmaz; güvenli fixture kullanılması, yürütme olmuş gibi sahte kayıt oluşturulmasına izin vermez.

## 8. Mevcut Koschei bileşenleriyle ilişki

| Mevcut bileşen | Yeni üründeki rol |
| --- | --- |
| Defense OS Phase 12C / LiteSVM | Güvenli ve default-off yürütme zemini; kendi başına savunma doğrulaması değildir |
| Gelecek stateful adversarial engine | Sürüm pinli saldırı dizilerini üretir ve yeniden oynatır |
| ARVIS Actor Investigation Engine | Gerçek olaylardan doğrulanmış aktör/taktik örüntüsü sağlar; kontrol sonucuna hükmetmez |
| Signed evidence/dossier altyapısı | Doğrulama raporunun bütünlük ve yeniden üretim katmanı olur |
| Webhook/alert altyapısı | Kontrol adapter'ı değildir; bağımsız collector olarak ayrıca kanıtlanmalıdır |

Actor ruleset `v1.0` ve Unified Radar ruleset `koschei-unified-radar-rules-v1.0.0` değişmez. Defense-validation sonucu Radar harf notunu değiştirmez ve `verdict_authority=false` sınırını korur.

## 9. Güvenlik sınırları

- Mainnet'e işlem gönderilmez.
- Cüzdan, private key, seed phrase veya signing material saklanmaz.
- Test edilen kontrolün production ayarı otomatik değiştirilmez.
- Otomatik müdahale veya para transferi yapılmaz.
- Kullanıcı tarafından verilen arbitrary shell command çalıştırılmaz.
- Fork/sandbox dışına kaçan vaka reddedilir.
- Her yüksek etkili gelecek çalışma owner/human approval ve default-off gate ister.
- Auth, entitlement, session ve verified-wallet yolları bu ürün diliminde değişmez.

## 10. Zincir stratejisi

Çekirdek evaluator zincirden bağımsıztır. Zincire özgü kısım adapter'dır:

```text
Solana adapter ┐
EVM adapter    ├─ canonical case + observation contract ─ deterministic evaluator
Tron adapter   ┘
```

İlk release Solana'dır; çünkü Koschei'nin LiteSVM, Solana evidence ve program-analysis altyapısı hazırdır. EVM/Tron desteği ancak aynı kanıt sözleşmesini bozmayan ayrı adapter ve fixture corpus'larıyla eklenir.

## 11. İlk dikey kesit

İlk merge edilebilir dilim yalnızca şunları içerir:

1. zincirden bağımsız deterministik evaluator;
2. gerçek fork/sandbox ve bağımsız observation kanıtını zorunlu kılan veri sözleşmesi;
3. attack + benign kontrol matrisi;
4. detection time ve lead time ölçümü;
5. late, miss, false-positive ve incomplete fail-closed testleri;
6. order-independent rapor hash'i;
7. hiçbir route, migration, worker action veya production gate aktivasyonu olmaması.

Sonraki dilim, Phase 12C yürütme kaydı ile evaluator arasındaki tek yönlü adapter olacaktır. İlk gerçek ürün kanıtı, owner-onaylı bir Solana senaryosunun iki farklı savunma ayarında aynı immutable fixture ile karşılaştırılmasıdır.

## 12. Kabul kriteri

İlk ürün kanıtı tamamlanmış sayılır yalnızca:

- en az bir gerçek, güvenli Solana fork/sandbox attack case çalışmışsa;
- eşlenmiş benign control çalışmışsa;
- bağımsız collector her iki gözlem penceresini hash'lemişse;
- bir zayıf ayar `FAILED`, düzeltilmiş ayar `VALIDATED` üretmişse;
- aynı immutable girdiler ikinci çalışmada aynı rapor hash'ini üretmişse;
- Go test/vet/build ve repository security gates geçmişse;
- hiçbir mainnet, custody, signing veya production-autonomy sınırı gevşememişse.

Bu aşamadan önce Koschei “savunma doğrulandı” pazarlama iddiası kullanmaz.

## 13. Tezi destekleyen dış referanslar

Bu kaynaklar Koschei teknik kanıtı değildir; problemin gerçekliğini ve bağımsız doğrulama ihtiyacını destekleyen pazar/uygulama referanslarıdır:

- [Hypernative — Security Theater vs. Real Detection](https://www.hypernative.io/insights/blog/security-theater-vs-real-detection-the-biggest-mistake-in-evaluating-monitoring-solutions): monitoring değerlendirmesinde doğrulanabilir sonuç, paralel gözlem veya sabit olaylarla yapılandırılmış benchmark ihtiyacı.
- [Forta — Testing and Debugging Detection Bots](https://www.forta.org/blog/testing-and-debugging-detection-bots): detection bot'larının geçmiş işlemlerle, false positive ve false negative vakalarıyla sınanması.
- [Security Alliance — SEAL Wargames](https://securityalliance.org/our-work/wargames): gerçekçi fork tabanlı protokol savunma tatbikatları.
- [MITRE AADAPT](https://aadapt.mitre.org/): dağıtık defter/Web3 saldırı taktiklerini senaryo corpus'una bağlamak için açık taksonomi.

Bu referanslar “hiç rakip yok” iddiası kurmaz. Koschei'nin iddiası daha dardır: mevcut araçları taklit etmek yerine, exact control configuration + gerçek yürütme + bağımsız observation + benign kontrol + deterministik evidence dossier sözleşmesini ürünün merkezi yapmak.
