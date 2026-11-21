'use strict';

(() => {
  if (globalThis.__CYBERNOVA_QUICK_SEND_V3__) return;
  globalThis.__CYBERNOVA_QUICK_SEND_V3__ = true;
  const MAX_TEXT_CHARS = 500000;
  const COMPOSER_SELECTORS = [
    '#prompt-textarea',
    '[data-testid="composer"] [contenteditable="true"]',
    'form [contenteditable="true"]',
    'main [contenteditable="true"]',
    'textarea'
  ];
  const SEND_BUTTON_SELECTORS = [
    'button[data-testid="send-button"]',
    'button[aria-label="Send prompt"]',
    'button[aria-label="Отправить"]',
    'button[aria-label*="Send"]',
    'button[aria-label*="Отправить"]',
    'form button[type="submit"]'
  ];

  function isVisible(element) {
    if (!element || !element.isConnected) return false;
    const style = getComputedStyle(element);
    return style.display !== 'none' && style.visibility !== 'hidden' &&
      element.getClientRects().length > 0;
  }
  function findComposer() {
    for (const selector of COMPOSER_SELECTORS) {
      const candidate = [...document.querySelectorAll(selector)].find(element =>
        isVisible(element) && !element.disabled &&
        element.getAttribute('aria-disabled') !== 'true');
      if (candidate) return candidate;
    }
    return null;
  }
  function waitForComposer(timeoutMs = 12000) {
    const existing = findComposer();
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve,reject) => {
      const observer = new MutationObserver(() => {
        const candidate = findComposer();
        if (candidate) {
          observer.disconnect();
          clearTimeout(timer);
          resolve(candidate);
        }
      });
      observer.observe(document.documentElement,{childList:true,subtree:true,attributes:true});
      const timer = setTimeout(() => {
        observer.disconnect();
        reject(new Error('chatgpt_composer_not_found'));
      },timeoutMs);
    });
  }
  function currentComposerText(element) {
    return typeof element.value === 'string' ? element.value :
      (element.innerText || element.textContent || '');
  }
  function appendText(element,text) {
    element.focus();
    const existing = currentComposerText(element);
    const insertion = (existing.trim() ? '\n\n' : '') + text;
    if (element.isContentEditable) {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(element);
      range.collapse(false);
      selection.removeAllRanges();
      selection.addRange(range);
      const inserted = document.execCommand('insertText',false,insertion);
      if (!inserted) {
        element.appendChild(document.createTextNode(insertion));
        element.dispatchEvent(new InputEvent('input',{
          bubbles:true,inputType:'insertText',data:insertion
        }));
      }
      return;
    }
    const prototype = element instanceof HTMLTextAreaElement ?
      HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const descriptor = Object.getOwnPropertyDescriptor(prototype,'value');
    if (descriptor?.set) descriptor.set.call(element,existing+insertion);
    else element.value = existing+insertion;
    element.dispatchEvent(new InputEvent('input',{
      bubbles:true,inputType:'insertText',data:insertion
    }));
    element.dispatchEvent(new Event('change',{bubbles:true}));
  }
  function findSendButton() {
    for (const selector of SEND_BUTTON_SELECTORS) {
      const button = [...document.querySelectorAll(selector)].find(isVisible);
      if (button) return button;
    }
    return null;
  }
  async function waitForSendButton(timeoutMs = 5000) {
    const started = Date.now();
    while (Date.now()-started < timeoutMs) {
      const button = findSendButton();
      if (button && !button.disabled && button.getAttribute('aria-disabled') !== 'true') return button;
      await new Promise(resolve => setTimeout(resolve,100));
    }
    throw new Error('chatgpt_send_button_not_ready');
  }
  function showToast(message,success=true) {
    const old = document.getElementById('cybernova-quick-send-toast');
    if (old) old.remove();
    const toast = document.createElement('div');
    toast.id = 'cybernova-quick-send-toast';
    toast.className = success ?
      'cybernova-quick-send-toast success' : 'cybernova-quick-send-toast error';
    toast.textContent = message;
    document.documentElement.appendChild(toast);
    setTimeout(() => toast.remove(),3200);
  }
  async function sendText(message) {
    const text = String(message.text || '');
    if (!text.trim()) throw new Error('empty_text');
    if (text.length > MAX_TEXT_CHARS) throw new Error('text_too_large');
    const composer = await waitForComposer();
    let prefix;
    if (message.sourceKind === 'clipboard') {
      prefix = 'Разбери скопированный вывод/текст:\n\n';
    } else {
      const source = String(message.sourceLabel || '').replace(/[<>\r\n]/g,'').slice(0,160);
      prefix = source ?
        'Разбери выделенный фрагмент со страницы '+source+':\n\n' :
        'Разбери выделенный фрагмент:\n\n';
    }
    appendText(composer,prefix+text);
    const sendButton = await waitForSendButton();
    sendButton.click();
    showToast('Cybernova: сообщение отправлено в ChatGPT',true);
    return {ok:true,sent:true};
  }
  chrome.runtime.onMessage.addListener((message,sender,sendResponse) => {
    if (message?.type !== 'CYBERNOVA_SEND_TEXT') return false;
    sendText(message).then(sendResponse).catch(error => {
      const reason = String(error?.message || 'send_failed');
      showToast('Cybernova: '+reason,false);
      sendResponse({ok:false,error:reason});
    });
    return true;
  });
})();
