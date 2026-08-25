(()=>{
'use strict';

const state={users:[],query:'',status:'all',plan:'all',wallet:'all',loading:false,refreshTimer:null};
const owner=()=>window.KoscheiOwner;
const $=id=>document.getElementById(id);
const arr=value=>Array.isArray(value)?value:[];
const esc=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const short=(value,head=9,tail=7)=>{const text=String(value||'');return text.length>head+tail+3?`${text.slice(0,head)}…${text.slice(-tail)}`:text||'—'};
const dateText=value=>{if(!value)return'—';const date=new Date(value);return Number.isNaN(date.getTime())?'—':new Intl.DateTimeFormat('tr-TR',{dateStyle:'short',timeStyle:'short'}).format(date)};
const planOf=user=>String(user?.plan_id||'free').toLowerCase();
const statusOf=user=>String(user?.status||'active').toLowerCase();
const hasWallet=user=>Boolean(String(user?.wallet_address||'').trim());

function reorderNav(root){
  if(!root)return;
  const customer=root.querySelector('[data-nav="customers"]');
  const social=root.querySelector('[data-social-studio-nav]');
  if(customer&&root.firstElementChild!==customer)root.prepend(customer);
  if(customer&&social&&customer.nextElementSibling!==social)customer.after(social);
}
function reorderNavigation(){reorderNav($('desktopNav'));reorderNav($('mobileNav'))}

function scheduleLoad(delay=120){
  clearTimeout(state.refreshTimer);
  state.refreshTimer=setTimeout(()=>{
    if($('page-customers')?.classList.contains('active'))load();
  },delay);
}

async function load(){
  if(state.loading)return;
  const root=$('customersContent');
  if(!root)return;
  state.loading=true;
  root.innerHTML='<div class="card loading">Müşteri dizini yükleniyor…</div>';
  try{
    const suffix=state.query?`?q=${encodeURIComponent(state.query)}`:'';
    const data=await owner().api('/api/owner/users'+suffix);
    state.users=arr(data.users);
    render();
  }catch(error){
    root.innerHTML=`<div class="card error-state"><div><b>Müşteri dizini yüklenemedi.</b><span>${esc(error.message||'Bilinmeyen hata')}</span></div><button class="btn small" id="customerDirectoryRetry" type="button">Tekrar dene</button></div>`;
    $('customerDirectoryRetry')?.addEventListener('click',()=>load());
  }finally{state.loading=false;}
}

function filteredUsers(){
  return state.users.filter(user=>{
    if(state.status!=='all'&&statusOf(user)!==state.status)return false;
    if(state.plan!=='all'&&planOf(user)!==state.plan)return false;
    if(state.wallet==='with'&&!hasWallet(user))return false;
    if(state.wallet==='without'&&hasWallet(user))return false;
    return true;
  });
}

function metric(label,value,foot,tone=''){return`<article class="customer-metric ${tone}"><span>${esc(label)}</span><b>${esc(value)}</b><small>${esc(foot)}</small></article>`}
function pill(value,type=''){return`<span class="customer-pill ${type}">${esc(value)}</span>`}

function render(){
  const root=$('customersContent');
  if(!root)return;
  const users=filteredUsers();
  const all=state.users;
  const active=all.filter(user=>statusOf(user)==='active').length;
  const banned=all.filter(user=>statusOf(user)==='banned').length;
  const removed=all.filter(user=>statusOf(user)==='removed').length;
  const wallets=all.filter(hasWallet).length;
  const paid=all.filter(user=>planOf(user)!=='free').length;
  const starter=all.filter(user=>planOf(user)==='starter').length;
  const professional=all.filter(user=>planOf(user)==='professional').length;
  const enterprise=all.filter(user=>planOf(user)==='enterprise').length;
  root.innerHTML=`<section class="owner-customer-directory" data-customer-directory="1">
    <div class="customer-hero">
      <div><span class="eyebrow">1 · MÜŞTERİLER</span><h2>Kim var, kim yok — tek ekranda.</h2><p>Gerçek kayıtlı hesapları, cüzdan bağını, paketi ve hesap durumunu doğrudan üretim müşteri tablosundan gösterir.</p></div>
      <button class="btn primary" id="customerDirectoryRefresh" type="button">Yenile</button>
    </div>
    <div class="customer-metrics">
      ${metric('Toplam müşteri',all.length,'Kayıtlı hesap','cyan')}
      ${metric('Aktif',active,'Kullanabilir','green')}
      ${metric('Cüzdan bağlı',wallets,`${Math.max(0,all.length-wallets)} hesaptan cüzdan yok`,'cyan')}
      ${metric('Ücretli paket',paid,`${starter} Starter · ${professional} Pro · ${enterprise} Enterprise`,'green')}
      ${metric('Yasaklı',banned,'Owner kontrolü','amber')}
      ${metric('Kaldırılmış',removed,'Erişimi kapalı','red')}
    </div>
    <article class="card customer-directory-card">
      <div class="customer-toolbar">
        <div class="customer-search"><input class="input" id="customerDirectorySearch" placeholder="E-posta, auth ID veya wallet" value="${esc(state.query)}"><button class="btn" id="customerDirectorySearchButton" type="button">Ara</button></div>
        <div class="customer-filters">
          <select class="input" id="customerStatusFilter"><option value="all">Tüm durumlar</option><option value="active">Aktif</option><option value="banned">Yasaklı</option><option value="removed">Kaldırılmış</option></select>
          <select class="input" id="customerPlanFilter"><option value="all">Tüm paketler</option><option value="free">Free</option><option value="starter">Starter</option><option value="professional">Professional</option><option value="enterprise">Enterprise</option></select>
          <select class="input" id="customerWalletFilter"><option value="all">Cüzdan: tümü</option><option value="with">Cüzdan var</option><option value="without">Cüzdan yok</option></select>
        </div>
      </div>
      <div class="customer-result-head"><b>${users.length} müşteri gösteriliyor</b><span>Kaynak: local auth + profiles + entitlements</span></div>
      <div class="table-wrap"><table class="table customer-table"><thead><tr><th>Müşteri</th><th>Cüzdan</th><th>Paket</th><th>Hesap</th><th>Son güncelleme</th><th>İşlem</th></tr></thead><tbody>
        ${users.length?users.map(user=>row(user)).join(''):'<tr><td colspan="6"><div class="empty">Bu filtrelerde müşteri yok.</div></td></tr>'}
      </tbody></table></div>
    </article>
  </section>`;
  $('customerStatusFilter').value=state.status;
  $('customerPlanFilter').value=state.plan;
  $('customerWalletFilter').value=state.wallet;
  bind();
}

function row(user){
  const plan=planOf(user);
  const status=statusOf(user);
  const wallet=String(user.wallet_address||'');
  const planClass=plan==='enterprise'?'enterprise':plan==='professional'?'professional':plan==='starter'?'starter':'free';
  const statusClass=status==='banned'||status==='removed'?'danger':'ok';
  return`<tr data-customer-row="${esc(user.id)}">
    <td><b>${esc(user.email||'—')}</b><div class="mono muted small">${esc(short(user.auth_subject,18,8))}</div></td>
    <td>${wallet?`<span class="mono">${esc(short(wallet,10,8))}</span><div>${pill('Cüzdan var','ok')}</div>`:`<span class="muted">Bağlı değil</span><div>${pill('Cüzdan yok','warn')}</div>`}</td>
    <td>${pill(plan.toUpperCase(),planClass)}<div class="muted small">${esc(user.active_entitlement_status||'No active package')}</div></td>
    <td>${pill(status.toUpperCase(),statusClass)}</td>
    <td>${esc(dateText(user.updated_at||user.created_at))}</td>
    <td><button class="btn small" data-customer-manage="${esc(user.id)}" type="button">Detay / Yönet</button></td>
  </tr>`;
}

function bind(){
  $('customerDirectoryRefresh')?.addEventListener('click',()=>load());
  $('customerDirectorySearchButton')?.addEventListener('click',()=>{state.query=$('customerDirectorySearch').value.trim();load();});
  $('customerDirectorySearch')?.addEventListener('keydown',event=>{if(event.key==='Enter'){state.query=event.currentTarget.value.trim();load();}});
  $('customerStatusFilter')?.addEventListener('change',event=>{state.status=event.currentTarget.value;render();});
  $('customerPlanFilter')?.addEventListener('change',event=>{state.plan=event.currentTarget.value;render();});
  $('customerWalletFilter')?.addEventListener('change',event=>{state.wallet=event.currentTarget.value;render();});
  document.querySelectorAll('[data-customer-manage]').forEach(button=>button.addEventListener('click',()=>manage(state.users.find(user=>String(user.id)===String(button.dataset.customerManage)))));
}

function closeCustomerModal(){const root=$('modalRoot');if(root)root.innerHTML='';}
function manage(user){
  if(!user)return;
  const root=$('modalRoot');if(!root)return;
  const status=statusOf(user),plan=planOf(user),wallet=String(user.wallet_address||'');
  const expires=user.entitlement_expires_at?dateText(user.entitlement_expires_at):'Süre sınırı yok / aktif paket yok';
  root.innerHTML=`<div class="modal-backdrop" data-customer-modal-backdrop><section class="modal" role="dialog" aria-modal="true" aria-label="Müşteri detayı">
    <div class="modal-head"><div><span class="eyebrow">MÜŞTERİ DETAYI</span><h2>${esc(user.email||'—')}</h2></div><button class="modal-close" data-customer-close type="button">×</button></div>
    <div class="metadata">
      <div><label>Hesap durumu</label><b>${esc(status.toUpperCase())}</b></div>
      <div><label>Paket</label><b>${esc(plan.toUpperCase())}</b></div>
      <div><label>Cüzdan</label><b class="mono">${esc(wallet||'Bağlı değil')}</b></div>
      <div><label>Auth subject</label><b class="mono">${esc(user.auth_subject||'—')}</b></div>
      <div><label>Kayıt</label><b>${esc(dateText(user.created_at))}</b></div>
      <div><label>Son güncelleme</label><b>${esc(dateText(user.updated_at||user.created_at))}</b></div>
      <div><label>Entitlement</label><b>${esc(user.active_entitlement_status||'No active package')}</b></div>
      <div><label>Paket bitişi</label><b>${esc(expires)}</b></div>
    </div>
    <div class="modal-actions">
      ${status==='banned'?'<button class="btn primary" data-customer-action="unban" type="button">Yasağı kaldır</button>':'<button class="btn warn" data-customer-action="ban" type="button">Kullanıcıyı yasakla</button>'}
      ${status!=='removed'?'<button class="btn danger" data-customer-action="remove" type="button">Erişimi kaldır</button>':''}
      <button class="btn" data-customer-close type="button">Kapat</button>
    </div>
    <div class="muted small section-gap">Bu işlemler Owner API üzerinden uygulanır ve müşteri kimliği e-posta/auth kaydı ile doğrulanır.</div>
  </section></div>`;
  root.querySelectorAll('[data-customer-close]').forEach(button=>button.addEventListener('click',closeCustomerModal));
  root.querySelector('[data-customer-modal-backdrop]')?.addEventListener('click',event=>{if(event.target===event.currentTarget)closeCustomerModal();});
  root.querySelectorAll('[data-customer-action]').forEach(button=>button.addEventListener('click',()=>runCustomerAction(user,button.dataset.customerAction,button)));
}

async function runCustomerAction(user,action,button){
  if(!user||!action)return;
  const label=action==='ban'?'yasaklansın':action==='unban'?'yasağı kaldırılsın':'erişimi kaldırılsın';
  if(!confirm(`${user.email} için ${label}?`))return;
  button.disabled=true;
  const previous=button.textContent;button.textContent='Uygulanıyor…';
  try{
    if(action==='ban'||action==='unban'){
      await owner().api('/api/owner/users/ban',{method:'POST',body:JSON.stringify({email:user.email,ban:action==='ban',reason:'owner_customer_directory'})});
    }else if(action==='remove'){
      await owner().api('/api/owner/users/remove',{method:'POST',body:JSON.stringify({email:user.email,reason:'owner_customer_directory'})});
    }
    closeCustomerModal();await load();
  }catch(error){button.disabled=false;button.textContent=previous;alert(error.message||'İşlem başarısız.');}
}

function boot(){
  reorderNavigation();
  const navObserver=new MutationObserver(()=>reorderNavigation());
  if($('desktopNav'))navObserver.observe($('desktopNav'),{childList:true});
  if($('mobileNav'))navObserver.observe($('mobileNav'),{childList:true});
  const root=$('customersContent');
  if(root){
    new MutationObserver(()=>{
      if(!$('page-customers')?.classList.contains('active'))return;
      if(root.querySelector('[data-customer-directory]'))return;
      scheduleLoad(80);
    }).observe(root,{childList:true});
  }
  document.addEventListener('click',event=>{if(event.target.closest('[data-nav="customers"]'))scheduleLoad(160);});
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&$('[data-customer-modal-backdrop]'))closeCustomerModal();});
  if($('page-customers')?.classList.contains('active'))scheduleLoad(60);
}

const timer=setInterval(()=>{if(window.KoscheiOwner&&$('customersContent')&&$('desktopNav')){clearInterval(timer);boot();}},100);
setTimeout(()=>clearInterval(timer),15000);
})();