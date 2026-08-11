'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const login=fs.readFileSync(path.join(root,'public','login.html'),'utf8');
const register=fs.readFileSync(path.join(root,'public','register.html'),'utf8');
const js=fs.readFileSync(path.join(root,'public','js','customer-auth-entry-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-auth-entry-v2.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}

requireText(login,'<html lang="en">','login html');
requireText(login,'data-auth-mode="login"','login mode');
requireText(login,'/css/customer-auth-entry-v2.css?v=1','login stylesheet');
requireText(login,'/js/customer-auth-entry-v2.js?v=1','login controller');
requireText(login,'Seed phrases, private keys, wallet approvals, and transaction signatures do not belong in the login flow.','login security boundary');
requireText(login,'id="authNext"','validated next-path display');
requireText(register,'KoscheiAuth','register existing auth client contract');

requireText(js,'KoscheiAuth.signIn(email,password)','login auth contract');
requireText(js,'KoscheiAuth.signUp(email,password)','shared registration contract');
requireText(js,'KoscheiAuth.nextPath','validated next-path contract');
requireText(js,'location.replace(next)','post-auth continuation');
requireText(js,"password!==confirm",'register password confirmation');
requireText(js,"params.get('registered')==='1'",'post-registration login state');
requireText(js,"if(KoscheiAuth.isLoggedIn?.()){location.replace(next);return;}",'existing-session redirect');

for(const forbidden of ['seed phrase','private key','signTransaction','signAllTransactions','sendTransaction','signAndSendTransaction']){
  if(js.toLowerCase().includes(forbidden.toLowerCase()))throw new Error(`auth controller must not contain wallet custody/transaction authority: ${forbidden}`);
}
if(/\bfetch\s*\(/.test(js))throw new Error('auth entry controller must use KoscheiAuth instead of raw fetch');
if(js.includes('localStorage.setItem(')||js.includes('sessionStorage.setItem('))throw new Error('auth entry controller must not invent client-side token storage');
requireText(css,'.auth-shell','auth layout styles');
requireText(css,'.auth-boundary','security boundary styles');
requireText(css,'.auth-message.bad','auth error styles');
console.log('customer auth entry v2 contract: ok');
