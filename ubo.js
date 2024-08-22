/// reinject-noscript.js
(function reinjectNoscriptElementContent() {
  console.log('ubo.js: reinject-noscript: init');
  const fn = function() {
    console.log('ubo.js: reinject-noscript: running');
    try {
      var noscripts = document.getElementsByTagName('noscript') || [];
      for (var i = 0, ilen = noscripts.length; i < ilen; i++) {
        if (noscripts[i] !== undefined && noscripts[i] !== null {
          var tpl = document.createElement('template');
          tpl.innerHTML = "<!-- ubo.js: reinject-noscript: start -->\n"
                        + noscripts[i].innerText
                        + "\n<!-- ubo.js: reinject-noscript: end -->";
          noscripts[i].parentNode.replaceChild(tpl.content, noscripts[i]);
        }
        else {
          console.log('ubo.js: reinject-noscript: weird = noscripts[' + i + 
                      '] not defined');
        }
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
})();
