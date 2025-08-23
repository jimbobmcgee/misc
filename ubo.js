/// reinject-noscript.js
(function reinjectNoscriptElementContent() {
  console.log('ubo.js: reinject-noscript: init (v=3.2)');
  
  const fn = function() {
    console.log('ubo.js: reinject-noscript: running');
    var noscripts = document.getElementsByTagName('noscript') || [];
    for (var i = noscripts.length - 1; i >= 0; i--) {
      console.log('ubo.js: reinject-noscript: noscript #' + i);
    }
  };
  
  if (document.readyState !== "complete") {
    document.addEventListener("DOMContentLoaded", fn);
  }
  else fn();
})();
