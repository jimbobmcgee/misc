/// noscript-to-span.js
function noscriptToSpan() {
  console.log('ubo.js: noscript-to-span: init');
  const fn = function() {
    console.log('ubo.js: noscript-to-span: running');
    try {
      var noscripts = document.getElementsByTagName('noscript');
      for (var i = 0, ilen = noscripts.length; i < ilen; i++) {
        var s = document.createElement('span');
        s.classList.add('ubo-was-noscript');
        s.innerHTML = noscripts[i].innerText;
        noscripts[i].parentNode.replaceChild(s, noscripts[i]);
      }
    }
    catch (e) {
      console.log('ubo.js: noscript-to-span: error = ' + e);
    }
  };
  if (document.readyState !== "complete") {
    document.addEventListener("DOMContentLoaded", fn);
  }
  else fn();
}
