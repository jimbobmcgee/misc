/// reinject-noscript.js
(function reinjectNoscriptElementContent() {
  window.alert('ubo.js outer');
  console.log('ubo.js: reinject-noscript: init (v=3.2)');

  var fn = function() {
    console.log('ubo.js: reinject-noscript: running');
    window.alert('ubo.js inner');
    var noscripts = document.getElementsByTagName('noscript') || [];
    for (var i = noscripts.length - 1; i >= 0; i--) {
    }
  };
  
  window.alert('ubo.js outer 2');
})();
