(() => {
  "use strict";

  if (window.__cybernovaTerminalPasteInstalled) return;
  window.__cybernovaTerminalPasteInstalled = true;

  const COMPOSER_SELECTOR = [
    "#prompt-textarea",
    '[data-testid="prompt-textarea"]',
    'textarea[placeholder]',
    '[contenteditable="true"][role="textbox"]'
  ].join(",");

  const SEND_SELECTOR = [
    'button[data-testid="send-button"]',
    'button[aria-label="Send prompt"]',
    'button[aria-label="Send message"]',
    'button[aria-label^="Send"]',
    'button[aria-label*="Отправ"]'
  ].join(",");

  const MAX_CLIPBOARD_CHARS = 100000;
  let busy = false;
  let toastHost;
  let toastNode;

  function ensureToast() {
    if (toastHost?.isConnected) return;
    toastHost = document.createElement("div");
    toastHost.id = "cybernova-terminal-paste-toast";
    Object.assign(toastHost.style, {
      position: "fixed",
      right: "22px",
      bottom: "22px",
      zIndex: "2147483647",
      pointerEvents: "none"
    });
    const shadow = toastHost.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      .toast {
        max-width: min(440px, calc(100vw - 44px));
        padding: 12px 16px;
        border: 1px solid #52675d;
        border-radius: 12px;
        background: #18231e;
        color: #eff8f2;
        box-shadow: 0 8px 28px rgba(0,0,0,.32);
        font: 13px/1.45 system-ui, sans-serif;
        white-space: pre-wrap;
      }
      .toast.error { border-color: #a65d5d; background: #2b1b1b; }
      .toast.success { border-color: #54866b; }
    `;
    toastNode = document.createElement("div");
    toastNode.className = "toast";
    shadow.append(style, toastNode);
    document.documentElement.append(toastHost);
  }

  let toastTimer = 0;
  function showToast(message, kind = "") {
    ensureToast();
    toastNode.className = "toast" + (kind ? " " + kind : "");
    toastNode.textContent = message;
    toastHost.style.display = "block";
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      if (toastHost) toastHost.style.display = "none";
    }, kind === "error" ? 5200 : 2600);
  }

  function findComposerFromTarget(target) {
    if (!(target instanceof Element)) return null;
    const candidate = target.closest(COMPOSER_SELECTOR);
    if (!candidate) return null;

    if (candidate.id === "prompt-textarea" ||
        candidate.getAttribute("data-testid") === "prompt-textarea") {
      return candidate;
    }

    const form = candidate.closest("form");
    if (form && form.querySelector(SEND_SELECTOR)) return candidate;

    if (candidate.getAttribute("role") === "textbox" &&
        candidate.closest("main")) {
      return candidate;
    }
    return null;
  }

  function findCurrentComposer(preferred) {
    if (preferred?.isConnected) return preferred;
    const primary = document.querySelector(
      '#prompt-textarea, [data-testid="prompt-textarea"], [contenteditable="true"][role="textbox"]'
    );
    if (primary) return primary;
    const form = [...document.querySelectorAll("form")].find(item =>
      item.querySelector(SEND_SELECTOR)
    );
    return form?.querySelector('textarea[placeholder], [contenteditable="true"]') || null;
  }

  function composerText(element) {
    if (!element) return "";
    if (element instanceof HTMLTextAreaElement ||
        element instanceof HTMLInputElement) {
      return element.value || "";
    }
    return element.innerText || element.textContent || "";
  }

  function setComposerText(element, text) {
    element.focus();

    if (element instanceof HTMLTextAreaElement ||
        element instanceof HTMLInputElement) {
      const prototype = Object.getPrototypeOf(element);
      const descriptor = Object.getOwnPropertyDescriptor(prototype, "value");
      if (descriptor?.set) descriptor.set.call(element, text);
      else element.value = text;
      element.dispatchEvent(new InputEvent("input", {
        bubbles: true,
        inputType: "insertText",
        data: text
      }));
      element.dispatchEvent(new Event("change", { bubbles: true }));
      return;
    }

    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);

    const inserted = document.execCommand("insertText", false, text);
    const current = composerText(element);
    if (!inserted || current.replace(/\r\n/g, "\n") !== text.replace(/\r\n/g, "\n")) {
      element.replaceChildren(document.createTextNode(text));
      element.dispatchEvent(new InputEvent("input", {
        bubbles: true,
        inputType: "insertText",
        data: text
      }));
    }
  }

  function findSendButton(composer) {
    const form = composer?.closest("form");
    return (form && form.querySelector(SEND_SELECTOR)) ||
      document.querySelector(SEND_SELECTOR);
  }

  function isDisabled(button) {
    return !button ||
      button.disabled ||
      button.getAttribute("aria-disabled") === "true";
  }

  async function waitForSendButton(composer, timeoutMs = 2200) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const button = findSendButton(composer);
      if (!isDisabled(button)) return button;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    return findSendButton(composer);
  }

  async function pasteAndSend(composer) {
    if (busy) return;
    busy = true;
    try {
      showToast("Читаю буфер обмена…");
      if (!navigator.clipboard?.readText) {
        showToast("Браузер не предоставил доступ к буферу обмена.", "error");
        return;
      }

      const text = await navigator.clipboard.readText();
      if (!text || !text.trim()) {
        showToast("Буфер обмена пуст. Сначала скопируй вывод из терминала.", "error");
        return;
      }
      if (text.length > MAX_CLIPBOARD_CHARS) {
        showToast("Вывод слишком большой (" + text.length +
          " символов). Лимит этого помощника — " +
          MAX_CLIPBOARD_CHARS + " символов.", "error");
        return;
      }

      const editor = findCurrentComposer(composer);
      if (!editor) {
        showToast("Не найдено поле сообщения ChatGPT.", "error");
        return;
      }
      if (composerText(editor).trim()) {
        showToast("Поле сообщения уже содержит черновик. Отправка отменена, чтобы не смешать тексты.", "error");
        editor.focus();
        return;
      }

      setComposerText(editor, text);
      const sendButton = await waitForSendButton(editor);
      if (isDisabled(sendButton)) {
        showToast("Текст вставлен, но кнопка отправки недоступна. Проверь поле и нажми Enter.", "error");
        editor.focus();
        return;
      }

      sendButton.click();
      showToast("Вывод передан в ChatGPT.", "success");
    } catch (error) {
      showToast("Не удалось прочитать буфер или отправить текст: " +
        (error?.message || String(error)), "error");
    } finally {
      busy = false;
    }
  }

  document.addEventListener("contextmenu", event => {
    const composer = findComposerFromTarget(event.target);
    if (!composer) return;

    // In the ChatGPT message field, right-click means:
    // read clipboard -> insert plain text -> click Send.
    // Outside the message field, the normal browser context menu is untouched.
    event.preventDefault();
    event.stopPropagation();
    pasteAndSend(composer);
  }, true);

  console.info("[Cybernova] Right-click-to-send is active on the ChatGPT composer.");
})();
