"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  function addField(parent, labelText, control) {
    const wrap = el("div", "model-config-field");
    const label = el("label", "", labelText);
    if (control.id) label.htmlFor = control.id;
    wrap.append(label, control);
    parent.append(wrap);
    return wrap;
  }

  function ensurePanel() {
    const tabs = $("profileTabs");
    const panels = $("profileDialog")?.querySelector(".profile-shell");
    if (!tabs || !panels || $("modelConfigPanel")) return;
    const tab = el("button", "profile-tab", "Модель");
    tab.type = "button";
    tab.dataset.profileTab = "model";
    tab.setAttribute("aria-selected", "false");
    tabs.append(tab);

    const panel = el("section", "profile-panel model-config-panel");
    panel.id = "modelConfigPanel";
    panel.dataset.profilePanel = "model";
    panel.hidden = true;
    panel.append(
      el("h3", "", "Модель исследователя"),
      el("p", "profile-help", "Провайдер, модель и API-ключ DeepSeek настраиваются здесь. Ключ хранится локально в каталоге данных Cybernova и никогда не возвращается интерфейсу. ChatGPT использует отдельный вход через аккаунт OpenAI.")
    );

    const grid = el("div", "model-config-grid");
    const provider = el("select");
    provider.id = "modelProvider";
    [
      ["ollama", "Локальная Ollama"],
      ["deepseek", "DeepSeek API"],
      ["openai_compatible", "Другой OpenAI-совместимый API"],
    ].forEach(([value, label]) => {
      const option = el("option", "", label);
      option.value = value;
      provider.append(option);
    });
    addField(grid, "Провайдер", provider);

    const model = el("input");
    model.id = "modelId";
    model.type = "text";
    model.maxLength = 160;
    model.autocomplete = "off";
    model.spellcheck = false;
    model.placeholder = "например, deepseek-chat";
    addField(grid, "Идентификатор модели", model);

    const base = el("input");
    base.id = "modelBaseUrl";
    base.type = "url";
    base.maxLength = 500;
    base.autocomplete = "url";
    base.placeholder = "https://api.deepseek.com";
    addField(grid, "Base URL API", base);

    const keyWrap = el("div", "model-config-key-row");
    const key = el("input");
    key.id = "modelApiKey";
    key.type = "password";
    key.maxLength = 10000;
    key.autocomplete = "new-password";
    key.placeholder = "Ключ не задан";
    const reveal = el("button", "model-config-reveal", "Показать");
    reveal.type = "button";
    reveal.addEventListener("click", () => {
      const visible = key.type === "text";
      key.type = visible ? "password" : "text";
      reveal.textContent = visible ? "Показать" : "Скрыть";
    });
    keyWrap.append(key, reveal);
    addField(grid, "API-ключ (пустое поле сохраняет текущий)", keyWrap);

    panel.append(grid);
    const keyStatus = el("p", "model-config-key-status", "Проверяем конфигурацию…");
    keyStatus.id = "modelKeyStatus";
    panel.append(keyStatus);

    const actions = el("div", "model-config-actions");
    const save = el("button", "profile-save", "Применить модель");
    save.type = "button";
    save.id = "modelConfigSave";
    const clear = el("button", "header-button", "Удалить сохранённый ключ");
    clear.type = "button";
    clear.id = "modelConfigClear";
    actions.append(save, clear);
    panel.append(actions);
    panel.append(el("p", "model-config-note", "Изменение применяется к следующим запросам без перезапуска Cybernova. Для DeepSeek укажи свой API-ключ и точный идентификатор модели. Не вставляй ключ ChatGPT: OAuth-подключение настраивается отдельно."));
    const uiPanel = panels.querySelector('[data-profile-panel="ui"]');
    uiPanel?.after(panel);
    if (!uiPanel) panels.append(panel);

    provider.addEventListener("change", updateProviderFields);
    save.addEventListener("click", saveModelConfig);
    clear.addEventListener("click", clearModelKey);
    updateProviderFields();
  }

  function updateProviderFields() {
    const provider = $("modelProvider");
    const base = $("modelBaseUrl");
    const key = $("modelApiKey");
    if (!provider || !base || !key) return;
    const value = provider.value;
    const remote = value !== "ollama";
    base.disabled = !remote;
    key.disabled = !remote;
    base.closest(".model-config-field").hidden = !remote;
    key.closest(".model-config-field").hidden = !remote;
    if (value === "deepseek" && (!base.value || !/api\.deepseek\.com/i.test(base.value))) {
      base.value = "https://api.deepseek.com";
    }
    if (value === "deepseek" && !/deepseek/i.test($("modelId").value)) {
      $("modelId").value = "deepseek-chat";
    }
  }

  async function loadModelConfig() {
    const status = $("modelKeyStatus");
    if (!status) return;
    status.textContent = "Загружаю параметры активной модели…";
    try {
      const response = await fetch("/api/model-config", {cache:"no-store"});
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || "Не удалось получить настройки модели");
      const config = data.settings || {};
      const deepseek = config.provider === "openai_compatible" &&
        /api\.deepseek\.com/i.test(config.base_url || "");
      $("modelProvider").value = config.provider === "ollama" ? "ollama" :
        deepseek ? "deepseek" : "openai_compatible";
      $("modelId").value = config.model || "";
      $("modelBaseUrl").value = config.base_url || "";
      $("modelApiKey").value = "";
      $("modelApiKey").placeholder = config.api_key_configured ?
        "Ключ сохранён · пустое поле оставит его без изменений" : "Вставь API-ключ";
      status.textContent = (config.api_key_hint || "Статус ключа неизвестен") +
        " · " + (config.restart_required ? "потребуется перезапуск" : "применяется без перезапуска");
      updateProviderFields();
    } catch (error) {
      status.textContent = "Ошибка загрузки: " + String(error.message || error);
    }
  }

  async function saveModelConfig() {
    const button = $("modelConfigSave");
    const status = $("modelKeyStatus");
    const providerChoice = $("modelProvider").value;
    const payload = {
      provider: providerChoice === "ollama" ? "ollama" : "openai_compatible",
      model: $("modelId").value.trim(),
      base_url: providerChoice === "deepseek" ? "https://api.deepseek.com" : $("modelBaseUrl").value.trim(),
      api_key: $("modelApiKey").value || null,
      clear_api_key: false,
    };
    button.disabled = true;
    status.textContent = "Проверяю параметры и применяю конфигурацию…";
    try {
      const response = await fetch("/api/model-config", {
        method:"POST", headers:{"Content-Type":"application/json"},
        body:JSON.stringify(payload), cache:"no-store",
      });
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || "Не удалось применить модель");
      $("modelApiKey").value = "";
      $("modelApiKey").placeholder = data.settings?.api_key_configured ?
        "Ключ сохранён · пустое поле оставит его без изменений" : "Вставь API-ключ";
      status.textContent = "Применено: " + (data.settings?.model || payload.model) +
        " · следующие запросы используют эту модель";
      const title = $("modelName");
      if (title && stateModeIsResearcher()) title.textContent = data.settings?.model || payload.model;
      window.dispatchEvent(new CustomEvent("cybernova:model-config-applied", {detail:data.settings || {}}));
    } catch (error) {
      status.textContent = "Не удалось применить: " + String(error.message || error);
    } finally {
      button.disabled = false;
    }
  }

  function stateModeIsResearcher() {
    return !$("modeChatGPT")?.classList.contains("selected");
  }

  async function clearModelKey() {
    if (!window.confirm("Удалить сохранённый API-ключ DeepSeek из локального хранилища Cybernova?")) return;
    const button = $("modelConfigClear");
    const status = $("modelKeyStatus");
    button.disabled = true;
    try {
      const response = await fetch("/api/model-config", {
        method:"POST", headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          provider:$("modelProvider").value === "ollama" ? "ollama" : "openai_compatible",
          model:$("modelId").value.trim(),
          base_url:$("modelProvider").value === "deepseek" ? "https://api.deepseek.com" : $("modelBaseUrl").value.trim(),
          api_key:null, clear_api_key:true,
        }), cache:"no-store",
      });
      const data = await response.json();
      if (!response.ok) throw Error(data.detail || "Не удалось удалить ключ");
      $("modelApiKey").value = "";
      $("modelApiKey").placeholder = "Ключ удалён";
      status.textContent = "Сохранённый ключ удалён.";
    } catch (error) {
      status.textContent = "Ошибка: " + String(error.message || error);
    } finally {
      button.disabled = false;
    }
  }

  function init() {
    ensurePanel();
    $("profileTabs")?.addEventListener("click", event => {
      const tab = event.target.closest("[data-profile-tab]");
      if (tab?.dataset.profileTab === "model") void loadModelConfig();
    });
  }
  document.addEventListener("DOMContentLoaded", init);
})();