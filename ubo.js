/// reinject-noscript.js
function reinjectNoscriptElementContent() {
  console.log('ubo.js: reinject-noscript: init');
  const fn = function() {
    console.log('ubo.js: reinject-noscript: running');
    try {
      var noscripts = document.getElementsByTagName('noscript');
      for (var i = 0, ilen = noscripts.length; i < ilen; i++) {
        var s = document.createDocumentFragment();
        s.classList.add('ubo-was-noscript');
        s.innerHTML = noscripts[i].innerText;
        noscripts[i].parentNode.replaceChild(s, noscripts[i]);
      }
    }
    catch (e) {
      console.log('ubo.js: reinject-noscript: error = ' + e);
    }
  };
  if (document.readyState !== "complete") {
    document.addEventListener("DOMContentLoaded", fn);
  }
  else fn();
}
