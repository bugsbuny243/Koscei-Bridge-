'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','pilot.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','integration-pilot-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','koschei.css'),'utf8');
const analytics=fs.readFileSync(path.join(root,'internal','handlers','analytics.go'),'utf8');
const feedback=fs.readFileSync(path.join(root,'internal','handlers','feedback.go'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

requireText(html,'<html lang="en">','pilot language');
requireText(html,'/scan?mode=deep','canonical Deep Scan route');
requireText(html,'/kosch','canonical KOSCH route');
requireText(html,'/transaction-firewall','B2B guard route');
requireText(html,'id="pilotForm"','pilot form');
requireText(html,'id="website"','honeypot field');
requireText(html,'id="pilotNotice"','accessible intake notice');
requireText(html,'does not provision API access, change KOSCH tier, create a customer entitlement','intake entitlement boundary');
requireText(html,'Do not submit a seed phrase, private key, API secret, authorization token, or customer personal data.','secret/privacy boundary');
requireText(html,'/js/integration-pilot-v2.js?v=1','external pilot controller');
if(html.includes('/security-radar'))throw new Error('pilot must not advertise legacy security-radar');
if(html.includes('/kosch-access'))throw new Error('pilot must not advertise legacy kosch-access');
forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,'inline runtime script');
forbid(html,/\son[a-z]+\s*=/i,'inline event handler');
forbid(html,/çıktı bazlı|output-based API access/i,'legacy output-based commercial model');

requireText(analytics,'if eventName == "customer_feedback"','analytics feedback routing');
requireText(analytics,'h.submitFeedbackFromAnalytics(w, r, req)','feedback handler delegation');
requireText(feedback,'"suggestion": true','pilot feedback category');
requireText(feedback,'h.Limiter.allow("customer-feedback:"+clientIP(r), 5, time.Hour)','feedback rate limit');
requireText(feedback,'if strings.TrimSpace(input.Website) != ""','honeypot contract');
requireText(feedback,'len([]rune(subject)) < 3 || len([]rune(subject)) > 160','subject bounds');
requireText(feedback,'len([]rune(message)) < 10 || len([]rune(message)) > 5000','message bounds');
requireText(feedback,'mail.ParseAddress(email)','server email validation');
requireText(feedback,'"feedback_id": id','stored feedback reference');

requireText(js,"fetch('/api/analytics/event'",'existing analytics intake endpoint');
requireText(js,"event_name:'customer_feedback'",'pilot feedback event');
requireText(js,"category:'suggestion'",'pilot suggestion category');
requireText(js,'website:fields.website','honeypot forwarding');
requireText(js,'page_url:pageURL()','query-free page URL');
requireText(js,"function pageURL(){return `${location.origin}${location.pathname}`;}",'query/hash exclusion');
requireText(js,'fields.decision.length<10||fields.success.length<10','client minimum content gate');
requireText(js,'if(message.length>5000)','client message upper bound');
requireText(js,"if(!response.ok||data?.ok!==true)",'server acceptance gate');
requireText(js,'inFlight=true;submit.disabled=true','duplicate submission guard');
requireText(js,'AbortController','bounded intake request');
forbid(js,/location\.href/,'query-bearing page URL forwarding');
forbid(js,/\.innerHTML\s*=/,'API-derived innerHTML');
forbid(js,/\b(?:localStorage|sessionStorage)\b/,'browser intake persistence');
forbid(js,/Authorization|X-API-Key/i,'credential header on public intake');
forbid(js,/\b(?:signMessage|signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,'wallet authority');

requireText(css,'.pilot-honeypot','honeypot styles');
requireText(css,'.pilot-notice.bad','intake error styles');
requireText(css,'@media(max-width:620px)','mobile pilot layout');
console.log('integration pilot v2 contract: ok');
