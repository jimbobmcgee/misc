'use strict';

/// noscriptToSpan
function noscriptToSpan() {
    console.log('ubo.js: noscriptToSpan');
    var noscripts = document.querySelectorAll
                  ? document.querySelectorAll('noscript')
                  : document.getElementsByTagName('noscript');
    
    for (var i = 0, ilen = noscripts.length; i < ilen; i++) {
        var s = document.createElement('span');
        s.classList.add('ubo-was-noscript');
        s.innerHTML = noscripts[i].innerText;
        noscripts[i].parentNode.replaceChild(s, noscripts[i]);
    }
}
