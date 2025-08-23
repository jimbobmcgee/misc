/// reinject-noscript.js
(function reinjectNoscriptElementContent() {
  window.alert('ubo.js outer');
  console.log('ubo.js: reinject-noscript: init (v=3.2)');

  var fn = function() {
    console.log('ubo.js: reinject-noscript: running');
    window.alert('ubo.js inner');
  };
  
  window.alert('ubo.js outer 2');
})();
