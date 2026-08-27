(()=>{
'use strict';
if(window.__koscheiCustomerCommandCenterV1)return;
window.__koscheiCustomerCommandCenterV1=true;

const routes=[
  {label:'Overview',href:'/dashboard',access:'PUBLIC'},
  {label:'Deep Investigation',href:'/scan?mode=deep',mode:'primary',access:'PUBLIC'},
  {label:'Transaction Preflight',href:'/scan?mode=transaction',access:'PROFESSIONAL+'},
  {label:'Evidence History',href:'/reports',access:'STARTER+'},
  {label:'Watchlist & Alerts',href:'/watchlist',access:'PROFESSIONAL+'},
  {label:'Public Evidence Cases',href:'/cases',access:'PUBLIC'},
  {label:'API Reference',href:'/docs/api',access:'PUBLIC · MIXED'},
  {label:'Account & Plan',href:'/account',access:'ACCOUNT'}
];

function activeFor(href){
  const current=location.pathname;
  if(href==='/dashboard')return current==='/dashboard';
  const path=href.split('?')[0];
  return path!=='/'&&current.startsWith(path);
}

function link(item){
  const a=document.createElement('a');
  a.href=item.href;
  const label=document.createElement('span');label.textContent=item.label;
  a.appendChild(label);
  if(item.access){const badge=document.createElement('small');badge.className='customer-capability-access';badge.textContent=item.access;a.appendChild(badge);}
  if(activeFor(item.href))a.dataset.active='true';
  if(item.mode==='primary')a.dataset.primary='true';
  return a;
}

function utilityLink(label,href){return link({label,href});}
function closePalette(){const node=document.querySelector('.customer-command-palette');if(node)node.hidden=true;}
function buildPalette(){
  const wrap=document.createElement('div');wrap.className='customer-command-palette';wrap.hidden=true;wrap.setAttribute('role','dialog');wrap.setAttribute('aria-modal','true');wrap.setAttribute('aria-label','Koschei command palette');
  const panel=document.createElement('div');panel.className='customer-command-palette__panel';
  const input=document.createElement('input');input.type='search';input.placeholder='Go to investigation, history, monitoring…';input.setAttribute('aria-label','Filter customer commands');
  const list=document.createElement('div');list.className='customer-command-palette__list';
  const render=()=>{const query=input.value.trim().toLowerCase();list.replaceChildren();routes.filter(item=>(item.label+' '+(item.access||'')).toLowerCase().includes(query)).forEach(item=>{const node=link(item);node.classList.add('customer-command-result');list.appendChild(node);});};
  input.addEventListener('input',render);wrap.addEventListener('click',event=>{if(event.target===wrap)closePalette();});panel.append(input,list);wrap.appendChild(panel);document.body.appendChild(wrap);render();return wrap;
}
function palette(){return document.querySelector('.customer-command-palette')||buildPalette();}
function openPalette(){const node=palette();node.hidden=false;node.querySelector('input')?.focus();}

function buildSidebar(){
  const aside=document.createElement('aside');
  aside.className='customer-sidebar';
  aside.id='customerSidebar';
  const brand=document.createElement('a');
  brand.href='/';brand.className='customer-sidebar__brand';
  brand.innerHTML='<span class="customer-sidebar__mark">K</span><span><strong>Koschei Web3</strong><small>Security Command Center</small></span>';
  const label=document.createElement('div');label.className='customer-section-label';label.textContent='Capabilities';
  const nav=document.createElement('nav');nav.className='customer-sidebar__nav';nav.setAttribute('aria-label','Customer security workspace');
  routes.forEach(item=>nav.appendChild(link(item)));
  const quick=document.createElement('button');quick.type='button';quick.className='customer-command-trigger';quick.textContent='Quick switch';quick.setAttribute('aria-keyshortcuts','Control+K Meta+K');quick.addEventListener('click',openPalette);nav.appendChild(quick);
  const footer=document.createElement('div');footer.className='customer-sidebar__footer';
  const status=document.createElement('span');status.innerHTML='<i class="customer-status-dot"></i>Access labels describe the current route surface; server authorization remains authoritative.';
  footer.append(status,utilityLink('Pricing','/pricing'),utilityLink('Home','/'));
  aside.append(brand,label,nav,footer);
  return aside;
}

function enhanceHeader(main){
  const header=main.querySelector('.top, .ops-nav');if(!header)return;
  const trigger=document.createElement('button');
  trigger.type='button';trigger.className=(header.classList.contains('ops-nav')?'ops-btn ':'btn ')+'customer-mobile-trigger';trigger.textContent='Menu';
  trigger.setAttribute('aria-controls','customerSidebar');trigger.setAttribute('aria-expanded','false');
  trigger.addEventListener('click',()=>{
    const open=document.body.classList.toggle('customer-nav-open');
    trigger.setAttribute('aria-expanded',open?'true':'false');
  });
  header.prepend(trigger);
}

function mount(){
  const main=document.querySelector('main.wrap, main.page, main.ops-page');
  if(!main||main.closest('.customer-app-shell'))return;
  const shell=document.createElement('div');shell.className='customer-app-shell';
  const content=document.createElement('div');content.className='customer-main';
  const parent=main.parentNode;
  parent.insertBefore(shell,main);
  shell.append(buildSidebar(),content);
  content.appendChild(main);
  enhanceHeader(content);
  document.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){event.preventDefault();openPalette();return;}if(event.key==='Escape')closePalette();});
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