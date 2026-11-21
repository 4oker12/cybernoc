'use strict';

const MENU_SELECTION = 'cybernova-send-selection';
const MENU_CLIPBOARD = 'cybernova-paste-clipboard-send';
const MENU_LOCAL_SELECTION = 'cybernova-send-selection-local';
const MAX_TEXT_CHARS = 500000;
const LOCAL_HOST = '127.0.0.1';
const LOCAL_PORT_MIN = 18785;
const LOCAL_PORT_MAX = 18805;

function isChatGPTUrl(url) {
  try {
    const parsed = new URL(url || '');
    return parsed.protocol === 'https:' &&
      (parsed.hostname === 'chatgpt.com' || parsed.hostname === 'chat.openai.com');
  } catch (_) { return false; }
}

// Chrome host permission patterns do not provide a port-range selector.
// Keep actual script injection and local actions restricted to this explicit interval.
function isAllowedLocalUrl(url) {
  try {
    const parsed = new URL(url || '');
    const port = Number(parsed.port);
    return parsed.protocol === 'http:' &&
      parsed.hostname === LOCAL_HOST &&
      Number.isInteger(port) &&
      port >= LOCAL_PORT_MIN &&
      port <= LOCAL_PORT_MAX;
  } catch (_) { return false; }
}

async function injectLocalContentScript(tab) {
  if (!tab?.id || !isAllowedLocalUrl(tab.url)) return false;
  try {
    await chrome.scripting.executeScript({
      target: {tabId: tab.id},
      files: ['content.js']
    });
    return true;
  } catch (error) {
    console.warn('[Cybernova Quick Send] local script injection failed:', error?.message || error);
    return false;
  }
}

async function injectExistingLocalTabs() {
  const tabs = await chrome.tabs.query({url: 'http://127.0.0.1/*'});
  for (const tab of tabs) {
    if (isAllowedLocalUrl(tab.url)) await injectLocalContentScript(tab);
  }
}

function createMenus() {
  chrome.contextMenus.removeAll(() => {
    if (chrome.runtime.lastError) {
      console.error('[Cybernova Quick Send] removeAll:', chrome.runtime.lastError.message);
      return;
    }
    chrome.contextMenus.create({
      id: MENU_SELECTION,
      title: 'Cybernova → отправить выделенное в ChatGPT',
      contexts: ['selection']
    });
    chrome.contextMenus.create({
      id: MENU_CLIPBOARD,
      title: 'Cybernova → вставить буфер и отправить',
      contexts: ['editable'],
      documentUrlPatterns: ['https://chatgpt.com/*', 'https://chat.openai.com/*']
    });
    chrome.contextMenus.create({
      id: MENU_LOCAL_SELECTION,
      title: 'Cybernova → отправить выделенное в локальную панель',
      contexts: ['selection'],
      documentUrlPatterns: ['http://127.0.0.1/*'],
      visible: false
    });
  });
}
function initializeExtension() {
  createMenus();
  injectExistingLocalTabs().catch(error =>
    console.warn('[Cybernova Quick Send] local tab scan failed:', error?.message || error));
}
chrome.runtime.onInstalled.addListener(initializeExtension);
chrome.runtime.onStartup.addListener(initializeExtension);

chrome.contextMenus.onShown.addListener((info, tab) => {
  const visible = isAllowedLocalUrl(tab?.url);
  chrome.contextMenus.update(MENU_LOCAL_SELECTION, {visible})
    .then(() => chrome.contextMenus.refresh())
    .catch(() => {});
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && isAllowedLocalUrl(tab?.url)) {
    void injectLocalContentScript(tab);
  }
});

function waitForTabComplete(tabId, timeoutMs) {
  return new Promise((resolve) => {
    let finished = false;
    const finish = (tab) => {
      if (finished) return;
      finished = true;
      chrome.tabs.onUpdated.removeListener(onUpdated);
      clearTimeout(timer);
      resolve(tab || null);
    };
    const onUpdated = (updatedId, changeInfo, tab) => {
      if (updatedId === tabId && changeInfo.status === 'complete') finish(tab);
    };
    const timer = setTimeout(() => finish(null), timeoutMs);
    chrome.tabs.onUpdated.addListener(onUpdated);
    chrome.tabs.get(tabId).then(tab => {
      if (tab.status === 'complete') finish(tab);
    }).catch(() => finish(null));
  });
}

async function findChatGPTTab(preferredTab) {
  if (preferredTab && isChatGPTUrl(preferredTab.url)) return preferredTab;
  const tabs = await chrome.tabs.query({
    url: ['https://chatgpt.com/*', 'https://chat.openai.com/*']
  });
  if (!tabs.length) {
    const created = await chrome.tabs.create({url:'https://chatgpt.com/'});
    await waitForTabComplete(created.id, 25000);
    return await chrome.tabs.get(created.id);
  }
  tabs.sort((a,b) => {
    const activeDelta = Number(Boolean(b.active)) - Number(Boolean(a.active));
    return activeDelta || Number(b.lastAccessed || 0) - Number(a.lastAccessed || 0);
  });
  return tabs[0];
}

async function sendToContent(tabId, payload) {
  try {
    return await chrome.tabs.sendMessage(tabId, payload);
  } catch (_) {
    await chrome.scripting.executeScript({target:{tabId}, files:['content.js']});
    await new Promise(resolve => setTimeout(resolve, 150));
    return await chrome.tabs.sendMessage(tabId, payload);
  }
}

async function setSuccessBadge() {
  await chrome.action.setBadgeBackgroundColor({color:'#16834a'});
  await chrome.action.setBadgeText({text:'OK'});
  await chrome.action.setTitle({title:'Cybernova Quick Send — отправлено'});
}

async function sendTextToChatGPT(text, preferredTab, sourceKind, sourceLabel) {
  const cleanText = String(text || '');
  if (!cleanText.trim()) throw new Error('empty_text');
  if (cleanText.length > MAX_TEXT_CHARS) throw new Error('text_too_large');
  const target = await findChatGPTTab(preferredTab);
  if (!target || !target.id) throw new Error('chatgpt_tab_unavailable');
  if (target.status !== 'complete') await waitForTabComplete(target.id, 20000);
  const response = await sendToContent(target.id, {
    type:'CYBERNOVA_SEND_TEXT',
    text:cleanText,
    sourceKind:sourceKind || 'selection',
    sourceLabel:sourceLabel || ''
  });
  if (!response || response.ok !== true) throw new Error(response?.error || 'chatgpt_send_failed');
  await setSuccessBadge();
  return response;
}

async function sendTextToLocalPage(text, localTab, sourceLabel) {
  const cleanText = String(text || '');
  if (!cleanText.trim()) throw new Error('empty_text');
  if (cleanText.length > MAX_TEXT_CHARS) throw new Error('text_too_large');
  if (!localTab?.id || !isAllowedLocalUrl(localTab.url)) {
    throw new Error('local_target_outside_allowed_ports_18785_18805');
  }
  if (localTab.status !== 'complete') await waitForTabComplete(localTab.id, 20000);
  await injectLocalContentScript(localTab);
  const response = await sendToContent(localTab.id, {
    type:'CYBERNOVA_SEND_TEXT',
    text:cleanText,
    sourceKind:'selection',
    sourceLabel:sourceLabel || '127.0.0.1 local panel'
  });
  if (!response || response.ok !== true) throw new Error(response?.error || 'local_page_send_failed');
  await setSuccessBadge();
  return response;
}

async function sendClipboardFromChatGPT(preferredTab, activateTab = false) {
  const target = await findChatGPTTab(preferredTab);
  if (!target || !target.id) throw new Error('chatgpt_tab_unavailable');
  if (activateTab && !target.active) {
    await chrome.tabs.update(target.id,{active:true});
    await new Promise(resolve => setTimeout(resolve,250));
  }
  if (target.status !== 'complete') await waitForTabComplete(target.id,20000);
  const response = await sendToContent(target.id,{
    type:'CYBERNOVA_READ_CLIPBOARD_AND_SEND'
  });
  if (!response || response.ok !== true) throw new Error(response?.error || 'clipboard_send_failed');
  await setSuccessBadge();
  return response;
}

async function reportError(error) {
  const message = String(error?.message || error || 'unknown_error');
  console.error('[Cybernova Quick Send]', message);
  await chrome.action.setBadgeBackgroundColor({color:'#b42318'});
  await chrome.action.setBadgeText({text:'!'});
  await chrome.action.setTitle({title:'Cybernova Quick Send — ошибка: '+message.slice(0,120)});
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  try {
    if (info.menuItemId === MENU_SELECTION) {
      const selected = String(info.selectionText || '');
      if (!selected.trim()) throw new Error('no_selected_text');
      let label = 'website';
      try { label = new URL(tab?.url || '').hostname; } catch (_) {}
      await sendTextToChatGPT(selected,tab,'selection',label);
      return;
    }
    if (info.menuItemId === MENU_LOCAL_SELECTION) {
      if (!isAllowedLocalUrl(tab?.url)) {
        throw new Error('local_target_outside_allowed_ports_18785_18805');
      }
      const selected = String(info.selectionText || '');
      if (!selected.trim()) throw new Error('no_selected_text');
      await sendTextToLocalPage(selected,tab,new URL(tab.url).host);
      return;
    }
    if (info.menuItemId === MENU_CLIPBOARD) {
      // Clipboard is read by the focused ChatGPT content script, never by an offscreen document.
      await sendClipboardFromChatGPT(tab,false);
    }
  } catch (error) { await reportError(error); }
});

chrome.commands.onCommand.addListener(async command => {
  if (command !== 'send-clipboard-to-chatgpt') return;
  try {
    await sendClipboardFromChatGPT(null,true);
  } catch (error) { await reportError(error); }
});

chrome.runtime.onMessage.addListener((message,sender,sendResponse) => {
  if (message?.type === 'CYBERNOVA_GET_STATUS') {
    sendResponse({ok:true,version:chrome.runtime.getManifest().version,
      architecture:'focused-chatgpt-content-script-plus-scoped-local-injection',
      local_ports:{host:LOCAL_HOST,min:LOCAL_PORT_MIN,max:LOCAL_PORT_MAX}});
  }
  return false;
});
