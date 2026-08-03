(()=>{
  if(document.getElementById('koscheiFeedbackButton')) return;
  const link=document.createElement('a');
  link.id='koscheiFeedbackButton';
  link.href='/feedback';
  link.setAttribute('aria-label','Send feedback');
  link.textContent='✦ Feedback';
  Object.assign(link.style,{
    position:'fixed',right:'16px',bottom:'16px',zIndex:'9999',
    display:'inline-flex',alignItems:'center',justifyContent:'center',gap:'8px',
    minHeight:'48px',padding:'0 18px',borderRadius:'999px',
    color:'#02100d',fontFamily:'Inter,system-ui,sans-serif',fontSize:'13px',fontWeight:'950',
    textDecoration:'none',background:'linear-gradient(135deg,#18ffb2,#24eaff)',
    boxShadow:'0 16px 45px #000b,0 0 28px #18ffb238',
    border:'1px solid #bffff0',transition:'transform .18s ease,box-shadow .18s ease'
  });
  link.addEventListener('mouseenter',()=>{link.style.transform='translateY(-2px)';link.style.boxShadow='0 20px 55px #000c,0 0 34px #18ffb250'});
  link.addEventListener('mouseleave',()=>{link.style.transform='';link.style.boxShadow='0 16px 45px #000b,0 0 28px #18ffb238'});
  document.body.appendChild(link);
})();