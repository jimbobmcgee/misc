/// reinject-noscript.js
(function reinjectNoscriptElementContent() {
  console.log('ubo.js: reinject-noscript: init (v=3.2)');
  
  const fn = function() {
    console.log('ubo.js: reinject-noscript: running');
    window.alert('ubo.js');
  };
  
  if (document.readyState !== "complete") {
    document.addEventListener("DOMContentLoaded", fn);
  }
  else fn();
})();
