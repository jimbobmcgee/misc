/// reinject-noscript.js
(function reinjectNoscriptElementContent() {
  console.log('ubo.js: reinject-noscript: init');
  const fn = function() {
    console.log('ubo.js: reinject-noscript: running');
    try {
      var noscripts = document.getElementsByTagName('noscript');
      for (var i = 0, ilen = noscripts.length; i < ilen; i++) {
        var tpl = document.createElement('template');
        tpl.innerHTML = noscripts[i].innerText;
        tpl.prepend(document.createComment("ubo.js: reinject-noscript start"));
        tpl.append(document.createComment("ubo.js: reinject-noscript end"));
        noscripts[i].parentNode.replaceChild(tpl.content, noscripts[i]);
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
