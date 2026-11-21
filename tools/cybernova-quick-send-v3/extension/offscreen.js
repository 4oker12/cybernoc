'use strict';

chrome.runtime.onMessage.addListener((message,sender,sendResponse) => {
  if (message?.target !== 'offscreen' ||
      message?.type !== 'CYBERNOVA_READ_CLIPBOARD') return false;
  (async () => {
    try {
      const text = await navigator.clipboard.readText();
      sendResponse({ok:true,text:String(text || '')});
    } catch (error) {
      sendResponse({ok:false,error:'clipboard_read_denied: '+String(error?.name || 'unknown')});
    }
  })();
  return true;
});
