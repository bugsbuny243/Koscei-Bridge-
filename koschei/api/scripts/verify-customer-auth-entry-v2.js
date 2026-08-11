'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const login=fs.readFileSync(path.join(root,'public','login.html'),'utf8');
const register=fs.readFileSync(path.join(root,'public','register.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-auth-entry-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-auth-entry-v2.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function requireOrder(source,first,second,label){if(source.indexOf(first)<0||source.indexOf(second)<0||source.indexOf(first)>=source.indexOf(second))throw new Error(`${label}: expected ${first} before ${second}`);}

for(const [html,mode,label] of [[login,'login','login html'],[register,'register','register html']]){
  requireText(html,'<html lang="en">',label);
  requireText(html,`data-auth-mode="${mode}"`,`${label} mode`);
  requireText(html,'/css/koschei-global-shell.css?v=4',`${label} global shell`);
  requireText(html,'/css/customer-auth-entry-v2.css?v=1',`${label} stylesheet`);
  requireText(html,'id="authForm"',`${label} shared form`);
  requireText(html,'id="authEmail"',`${label} email field`);
  requireText(html,'id="authPassword"',`${label} password field`);
  requireText(html,'id="authSubmit"',`${label} submit control`);
  requireText(html,'id="authMessage"',`${label} status surface`);
  requireText(html,'id="authNext"',`${label} validated next-path display`);
  requireText(html,'id="authSwitchLink"',`${label} auth switch`);
  requireText(html,'/js/koschei-auth.js?v=33',`${label} existing auth client`);
  requireText(html,'/js/customer-auth-entry-v2.js?v=1',`${label} shared controller`);
  requireOrder(html,'/js/koschei-auth.js?v=33','/js/customer-auth-entry-v2.js?v=1',`${label} script order`);
  if(/<script(?![^>]*\bsrc=)[^>]*>/i.test(html))throw new Error(`${label}: inline authentication scripts are not allowed`);
}
requireText(login,'Seed phrases, private keys, wallet approvals, and transaction signatures do not belong in the login flow.','login security boundary');
requireText(register,'Registration cannot sign transactions, request wallet approvals, or grant holder access by itself.','register security boundary');
requireText(register,'id="authConfirm"','register password confirmation field');
requireText(register,'minlength="8"','register password minimum');

requireText(js,'KoscheiAuth.signIn(email,password)','login auth contract');
requireText(js,'KoscheiAuth.signUp(email,password)','registration auth contract');
requireText(js,"KoscheiAuth.nextPath('/dashboard')",'validated next-path contract');
requireText(js,'location.replace(next)','post-auth continuation');
requireText(js,"password.length<8",'register password minimum enforcement');
requireText(js,"password!==confirm",'register password confirmation');
requireText(js,"params.get('registered')==='1'",'post-registration login state');
requireText(js,"switchLink.href=switchURL(next)",'cross-auth continuation preservation');
requireText(js,"if(KoscheiAuth.isLoggedIn?.()){location.replace(next);return;}",'existing-session redirect');

for(const forbidden of ['seed phrase','private key','signTransaction','signAllTransactions','sendTransaction','signAndSendTransaction']){
  if(js.toLowerCase().includes(forbidden.toLowerCase()))throw new Error(`auth controller must not contain wallet custody/transaction authority: ${forbidden}`);
}
if(/\bfetch\s*\(/.test(js))throw new Error('auth entry controller must use KoscheiAuth instead of raw fetch');
if(js.includes('localStorage.setItem(')||js.includes('sessionStorage.setItem('))throw new Error('auth entry controller must not invent client-side token storage');
requireText(css,'.auth-shell','auth layout styles');
requireText(css,'.auth-boundary','security boundary styles');
requireText(css,'.auth-message.bad','auth error styles');
requireText(css,'@media(max-width:560px)','mobile auth layout');
console.log('customer auth entry v2 contract: ok');
