(()=>{
'use strict';
if(window.__koscheiCustomerCommandCenterV1)return;
window.__koscheiCustomerCommandCenterV1=true;

const routes=[
  ['Overview','/dashboard'],
  ['Deep Investigation','/scan?mode=deep','primary'],
  ['Evidence History','/reports'],
  ['Watchlist & Alerts','/watchlist'],
  ['Public Evidence Cases','/cases'],
  ['API Reference','/docs/api'],
  ['Account & Plan','/account']
];

function activeFor(href){
  const current=location.pathname;
  if(href==='/dashboard')return current==='/dashboard';
  const path=href.split('?')[0];
  return path!=='/'&&current.startsWith(path);
}

function link(label,href,mode){
  const a=document.createElement('a');
  a.href=href;a.textContent=label;
  if(activeFor(href))a.dataset.active='true';
  if(mode==='primary')a.dataset.primary='true';
  return a;
}

function buildSidebar(){
  const aside=document.createElement('aside');
  aside.className='customer-sidebar';
  aside.id='customerSidebar';
  const brand=document.createElement('a');
  brand.href='/';brand.className='customer-sidebar__brand';
  brand.innerHTML='<span class="customer-sidebar__mark">K</span><span><strong>Koschei Web3</strong><small>Security Command Center</small></span>';
  const label=document.createElement('div');label.className='customer-section-label';label.textContent='Workspace';
  const nav=document.createElement('nav');nav.className='customer-sidebar__nav';nav.setAttribute('aria-label','Customer security workspace');
  routes.forEach(([name,href,mode])=>nav.appendChild(link(name,href,mode)));
  const footer=document.createElement('div');footer.className='customer-sidebar__footer';
  const status=document.createElement('span');status.innerHTML='<i class="customer-status-dot"></i>Evidence-first security workspace';
  footer.append(status,link('Pricing','/pricing'),link('Home','/'));
  aside.append(brand,label,nav,footer);
  return aside;
}

function enhanceHeader(main){
  const header=main.querySelector('.top');if(!header)return;
  const trigger=document.createElement('button');
  trigger.type='button';trigger.className='btn customer-mobile-trigger';trigger.textContent='Menu';
  trigger.setAttribute('aria-controls','customerSidebar');trigger.setAttribute('aria-expanded','false');
  trigger.addEventListener('click',()=>{
    const open=document.body.classList.toggle('customer-nav-open');
    trigger.setAttribute('aria-expanded',open?'true':'false');
  });
  header.prepend(trigger);
}

function mount(){
  const main=document.querySelector('main.wrap');
  if(!main||main.closest('.customer-app-shell'))return;
  const shell=document.createElement('div');shell.className='customer-app-shell';
  const content=document.createElement('div');content.className='customer-main';
  const parent=main.parentNode;
  parent.insertBefore(shell,main);
  shell.append(buildSidebar(),content);
  content.appendChild(main);
  enhanceHeader(content);
  document.addEventListener('click',event=>{
    if(!document.body.classList.contains('customer-nav-open'))return;
    const sidebar=document.getElementById('customerSidebar');
    const trigger=content.querySelector('.customer-mobile-trigger');
    if(sidebar?.contains(event.target)||trigger?.contains(event.target))return;
    document.body.classList.remove('customer-nav-open');
    trigger?.setAttribute('aria-expanded','false');
  });
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mount);else mount();
})();