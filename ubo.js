'use strict';

/// noscript-to-span.js
function noscriptToSpan() {
    console.log('ubo.js: noscript-to-span: starting');
    
    const fn = func() {
        console.log('ubo.js: noscript-to-span: running');
        
        try {
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
        catch (e) {
            console.log('ubo.js: noscript-to-span: error = ' + e);
        }
    };

    const observer = new MutationObserver(fn);
    
	observer.observe(document.documentElement, { 
        attributes: true, 
        childList: true, 
        subtree: true
    });
    
	if (document.readyState === "complete") { 
        self.setTimeout(func() {
            console.log('ubo.js: noscript-to-span: disconnecting');
            observer.disconnect();
        }, 67);  
    }
}

