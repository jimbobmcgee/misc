'use strict';

/// noscriptToSpan
/// world ISOLATED
function noscriptToSpan() {
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
