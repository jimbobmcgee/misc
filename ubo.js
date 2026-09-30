/// reinject-noscript.js
(function reinjectNoscriptElementContent() {
  console.log('ubo.js: reinject-noscript: init v4.2');
  const fn = function() {
    console.log('ubo.js: reinject-noscript: running');
    try {
      var noscripts = document.getElementsByTagName('noscript') || [];
      for (var i = noscripts.length - 1; i >= 0; i--) {
        if (noscripts[i] !== undefined && noscripts[i] !== null) {
          var tpl = document.createElement('template');
          tpl.innerHTML = "<!-- ubo.js: reinject-noscript: start -->\n"
                        + noscripts[i].innerText
                        + "\n<!-- ubo.js: reinject-noscript: end -->";
          var metas = tpl.content.querySelectorAll("meta[http-equiv=refresh]");
          for (var j = metas.length - 1; j >= 0; j--) {
            console.log('ubo.js: reinject-noscript: suppressing refresh: ' + metas[j].content);
            var suppressed = document.createComment("ubo.js: suppress-refresh: " + metas[j].content);
            metas[j].replaceWith(suppressed);
          }
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
