/// reinject-noscript.js
(function reinjectNoscriptElementContent() {
  console.log('ubo.js: reinject-noscript: init (v=3)');
  const fn = function() {
    window.alert('ubo.js: wtf is going on here?');
  };
  if (document.readyState !== "complete") {
    document.addEventListener("DOMContentLoaded", fn);
  }
  else fn();
})();
