'use strict';

const MENU_SELECTION = 'cybernova-send-selection';
const MENU_CLIPBOARD = 'cybernova-paste-clipboard-send';
const OFFSCREEN_PATH = 'offscreen.html';
const MAX_TEXT_CHARS = 500000;
let offscreenCreating = null;

function isChatGPTUrl(url) {
  try {
    const parsed = new URL(url || '');
    return parsed.protocol === 'https:' &&
      (parsed.hostname === 'chatgpt.com' || parsed.hostname === 'chat.openai.com');
  } catch (_) { return false; }
}

function createMenus() {
  chrome.contextMenus.removeAll(() => {
    if (chrome.runtime.lastError) return;
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
  });
}
chrome.runtime.onInstalled.addListener(createMenus);
chrome.runtime.onStartup.addListener(createMenus);

async function ensureOffscreenDocument() {
  const url = chrome.runtime.getURL(OFFSCREEN_PATH);
  const contexts = await chrome.runtime.getContexts({
    contextTypes: ['OFFSCREEN_DOCUMENT'],
    documentUrls: [url]
  });
  if (contexts.length) return;
  if (!offscreenCreating) {
    offscreenCreating = chrome.offscreen.createDocument({
      url: OFFSCREEN_PATH,
      reasons: ['CLIPBOARD'],
      justification: 'Read clipboard text only after the user explicitly selects the Cybernova paste-and-send command.'
    }).finally(() => { offscreenCreating = null; });
  }
  await offscreenCreating;
}

async function readClipboardText() {
  await ensureOffscreenDocument();
  const result = await chrome.runtime.sendMessage({
    target: 'offscreen',
    type: 'CYBERNOVA_READ_CLIPBOARD'
  });
  if (!result || result.ok !== true) throw new Error(result?.error || 'clipboard_read_failed');
  const text = String(result.text || '');
  if (!text.trim()) throw new Error('clipboard_empty');
  if (text.length > MAX_TEXT_CHARS) throw new Error('clipboard_too_large');
  return text;
}

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
  await chrome.action.setBadgeBackgroundColor({color:'#16834a'});
  await chrome.action.setBadgeText({text:'OK'});
  await chrome.action.setTitle({title:'Cybernova Quick Send — отправлено в ChatGPT'});
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
      await sendTextToChatGPT(selected, tab, 'selection', label);
      return;
    }
    if (info.menuItemId === MENU_CLIPBOARD) {
      const text = await readClipboardText();
      await sendTextToChatGPT(text, tab, 'clipboard', 'Windows clipboard');
    }
  } catch (error) { await reportError(error); }
});

chrome.commands.onCommand.addListener(async command => {
  if (command !== 'send-clipboard-to-chatgpt') return;
  try {
    const text = await readClipboardText();
    await sendTextToChatGPT(text, null, 'clipboard', 'Windows clipboard');
  } catch (error) { await reportError(error); }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.target === 'offscreen') return false;
  if (message?.type === 'CYBERNOVA_GET_STATUS') {
    sendResponse({ok:true, version:chrome.runtime.getManifest().version,
      architecture:'extension-content-script-no-local-server'});
  }
  return false;
});
