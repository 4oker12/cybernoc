"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const create = (tag, cls, text) => {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined) el.textContent = text;
    return el;
  };

  function compactToolGroups(root) {
    root.querySelectorAll(".inline-tools:not([data-compact])").forEach(container => {
      const items = Array.from(container.children).filter(item => item.tagName === "DETAILS");
      if (!items.length) return;
      const errors = items.filter(item => /ошибка/i.test(item.querySelector("summary")?.textContent || "")).length;
      const names = items.map(item => (item.querySelector("summary")?.textContent || "")
        .replace(/\s*·\s*Ошибка\s*/i, "").trim()).filter(Boolean);
      const batch = create("details", "tool-batch");
      const summary = create("summary", "tool-batch-summary");
      const title = create("span", "tool-batch-title", "Инструменты");
      const count = create("span", "tool-batch-count", String(items.length));
      const state = create("span", "tool-batch-state",
        errors ? errors + " с ошибкой" : "выполнено");
      const preview = create("span", "tool-batch-preview",
        names.slice(0, 3).join(" · ") + (names.length > 3 ? " · +" + (names.length - 3) : ""));
      summary.append(title, count, state, preview);
      const list = create("div", "tool-batch-list");
      items.forEach(item => {
        item.classList.add("tool-batch-item");
        list.append(item);
      });
      batch.append(summary, list);
      container.replaceChildren(batch);
      container.dataset.compact = "true";
    });
  }

  let askButton = null;
  let selectedText = "";
  function hideAsk() {
    if (askButton) askButton.hidden = true;
    selectedText = "";
  }
  function ensureAskButton() {
    if (askButton) return;
    askButton = create("button", "selection-ask", "Спросить");
    askButton.type = "button";
    askButton.hidden = true;
    askButton.setAttribute("aria-label", "Спросить об выделенном фрагменте");
    askButton.addEventListener("pointerdown", event => event.preventDefault());
    askButton.addEventListener("click", () => {
      if (!selectedText) return;
      const input = $("messageInput");
      const quote = selectedText.slice(0, 3000);
      const prompt = "Разбери выделенный фрагмент из предыдущего ответа:\n\n> " +
        quote.replace(/\n/g, "\n> ") +
        "\n\nОбъясни его смысл и связь с текущей задачей.";
      input.value = prompt;
      input.focus();
      input.dispatchEvent(new Event("input", {bubbles:true}));
      hideAsk();
      window.getSelection()?.removeAllRanges();
    });
    document.body.append(askButton);
  }
  function updateSelectionAction() {
    ensureAskButton();
    const selection = window.getSelection();
    if (!selection || selection.isCollapsed || !selection.rangeCount) {
      hideAsk();
      return;
    }
    const text = selection.toString().trim();
    if (!text || text.length < 3) {
      hideAsk();
      return;
    }
    const anchor = selection.anchorNode?.nodeType === Node.ELEMENT_NODE
      ? selection.anchorNode : selection.anchorNode?.parentElement;
    const body = anchor?.closest?.(".message-body");
    const message = body?.closest?.(".chat-msg");
    if (!body || !message || message.classList.contains("from-user") ||
        message.classList.contains("working")) {
      hideAsk();
      return;
    }
    const rect = selection.getRangeAt(0).getBoundingClientRect();
    if (!rect || (!rect.width && !rect.height)) {
      hideAsk();
      return;
    }
    selectedText = text;
    askButton.hidden = false;
    const width = askButton.offsetWidth || 90;
    const left = Math.max(8, Math.min(window.innerWidth - width - 8, rect.left + rect.width / 2 - width / 2));
    const top = Math.max(8, rect.top - 42);
    askButton.style.left = left + "px";
    askButton.style.top = top + "px";
  }

  function installResponsiveRunState() {
    const input = $("messageInput");
    const root = $("messages");
    if (!input || !root) return;
    const sync = () => {
      const active = !!document.querySelector(".chat-msg.working");
      document.documentElement.classList.toggle("model-running", active);
      // Keep the composer editable. send() still rejects a second concurrent
      // turn, but the user can prepare the next question while the model works.
      if (active && input.disabled) input.disabled = false;
    };
    const observer = new MutationObserver(sync);
    observer.observe(document.body, {subtree:true, childList:true, attributes:true, attributeFilter:["class","disabled"]});
    sync();
  }

  function init() {
    ensureAskButton();
    document.addEventListener("selectionchange", updateSelectionAction);
    window.addEventListener("scroll", hideAsk, true);
    window.addEventListener("resize", hideAsk);
    document.addEventListener("pointerdown", event => {
      if (askButton && !askButton.contains(event.target)) hideAsk();
    });
    const messages = $("messages");
    const gptMessages = $("gptMessages");
    const observer = new MutationObserver(() => {
      if (messages) compactToolGroups(messages);
      if (gptMessages) compactToolGroups(gptMessages);
    });
    [messages, gptMessages].filter(Boolean).forEach(root =>
      observer.observe(root, {subtree:true, childList:true}));
    compactToolGroups(messages || document);
    compactToolGroups(gptMessages || document);
    document.addEventListener("click", event => {
      const suggestion = event.target.closest("[data-prompt]");
      if (!suggestion || !suggestion.classList.contains("followup-question")) return;
      const box = suggestion.closest(".followup-box");
      if (box) box.remove();
    });
    installResponsiveRunState();
  }
  document.addEventListener("DOMContentLoaded", init);
})();