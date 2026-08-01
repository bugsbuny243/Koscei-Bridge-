(function(root,factory){
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  root.KoscheiEnforcementTrustAnchor=api;
})(typeof globalThis!=='undefined'?globalThis:this,function(){
  'use strict';

  const VERSION='koschei-enforcement-trust-anchor-v1';
  const CURRENT_KEY_ID='tgk_c7a9c6f81e4acb98';
  const PINNED_KEYS=Object.freeze({
    [CURRENT_KEY_ID]:'lCXYBwWBUlws5nZj7cb2uBs1+AnXvSXVK6v9iwKs8k4='
  });

  function pinnedKeys(){
    return Object.assign({},PINNED_KEYS);
  }

  return Object.freeze({
    VERSION,
    CURRENT_KEY_ID,
    PINNED_KEYS,
    pinnedKeys
  });
});
