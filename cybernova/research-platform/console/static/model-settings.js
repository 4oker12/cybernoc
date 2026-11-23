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

    const preset = el("select");
    preset.id = "modelPreset";
    [
      ["deepseek-flash", "DeepSeek Flash — быстрее"],
      ["deepseek-v4-pro", "DeepSeek V4 Pro — сложные задачи"],
      ["custom", "Другой идентификатор…"],
    ].forEach(([value, label]) => {
      const option = el("option", "", label);
      option.value = value;
      preset.append(option);
    });
    addField(grid, "Модель DeepSeek", preset);

    const effort = el("select");
    effort.id = "modelReasoningEffort";
    [
      ["none", "Выкл — без глубоких рассуждений"],
      ["low", "Low — быстро"],
      ["high", "High — подробно (по умолчанию)"],
      ["max", "Max — максимальная глубина"],
    ].forEach(([value, label]) => {
      const option = el("option", "", label);
      option.value = value;
      effort.append(option);
    });
    effort.value = "high";
    addField(grid, "Глубина рассуждений", effort);
    panel.append(el("p", "model-reasoning-note",
      "Pro и Max могут увеличить время ответа и расходы на API. Flash поддерживает изображения; Pro — только текст."));

    const model = el("input");
    model.id = "modelId";
    model.type = "text";
    model.maxLength = 160;
    model.autocomplete = "off";
    model.spellcheck = false;
    model.placeholder = "например, deepseek-flash";
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
    const save = el("button", "profile-save", "Подключить и проверить");
    save.type = "button";
    save.id = "modelConfigSave";
    actions.append(save);
    panel.append(actions);
    panel.append(el("p", "model-config-note", "Настройки вступают в силу со следующего запроса без перезапуска. При переключении Flash / Pro используется сохранённый локально API-ключ; в чат ключ не отправляй. ChatGPT подключается отдельно."));
    const uiPanel = panels.querySelector('[data-profile-panel="ui"]');
    uiPanel?.after(panel);
    if (!uiPanel) panels.append(panel);

    provider.addEventListener("change", () => {
      if (provider.value === "deepseek" &&
          !["deepseek-flash", "deepseek-v4-pro"].includes(model.value.trim())) {
        model.value = "deepseek-flash";
        preset.value = "deepseek-flash";
      }
      updateProviderFields();
    });
    preset.addEventListener("change", () => {
      if (preset.value !== "custom") model.value = preset.value;
      updateProviderFields();
    });
    save.addEventListener("click", saveModelConfig);
    updateProviderFields();
  }

  function updateProviderFields() {
    const provider = $("modelProvider");
    const base = $("modelBaseUrl");
    const key = $("modelApiKey");
    if (!provider || !base || !key) return;
    const value = provider.value;
    const remote = value !== "ollama";
    const isDeepseek = value === "deepseek";
    $("modelPreset").closest(".model-config-field").hidden = !isDeepseek;
    $("modelReasoningEffort").closest(".model-config-field").hidden = !isDeepseek;
    const reasoningNote = document.querySelector("#modelConfigPanel .model-reasoning-note");
    if (reasoningNote) reasoningNote.hidden = !isDeepseek;
    $("modelId").closest(".model-config-field").hidden = isDeepseek &&
      $("modelPreset").value !== "custom";
    base.disabled = !remote;
    key.disabled = !remote;
    base.closest(".model-config-field").hidden = !remote;
    key.closest(".model-config-field").hidden = !remote;
    if (value === "deepseek" && (!base.value || !/api\.deepseek\.com/i.test(base.value))) {
      base.value = "https://api.deepseek.com";
    }
    if (value === "deepseek" && (
      !/deepseek/i.test($("modelId").value) ||
      ["deepseek-chat", "deepseek-reasoner"].includes($("modelId").value.trim())
    )) {
      $("modelId").value = "deepseek-flash";
    }
  }

  function updateQuickButton(config) {
    const button = $("modelQuickSettings");
    if (!button) return;
    const deepseek = config.provider === "openai_compatible" &&
      /api\.deepseek\.com/i.test(config.base_url || "") &&
      /^deepseek-/.test(config.model || "");
    const effort = ["none", "low", "high", "max"].includes(config.reasoning_effort) ?
      config.reasoning_effort : "high";
    button.dataset.deepseek = String(deepseek);
    button.textContent = "Глубина: " + effort.toUpperCase() + " ▾";
    button.title = "Выбрать Flash / Pro и глубину рассуждений (сейчас " + effort.toUpperCase() + ")";
    button.hidden = !deepseek || !$("modeQwen")?.classList.contains("selected");
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
      $("modelPreset").value = ["deepseek-flash", "deepseek-v4-pro"].includes(config.model) ?
        config.model : "custom";
      $("modelReasoningEffort").value =
        ["none", "low", "high", "max"].includes(config.reasoning_effort) ?
        config.reasoning_effort : "high";
      $("modelBaseUrl").value = config.base_url || "";
      $("modelApiKey").value = "";
      $("modelApiKey").placeholder = config.api_key_configured ?
        "Ключ сохранён · пустое поле оставит его без изменений" : "Вставь API-ключ";
      status.textContent = (config.api_key_hint || "Статус ключа неизвестен") +
        " · " + (config.restart_required ? "потребуется перезапуск" : "применяется без перезапуска");
      updateProviderFields();
      updateQuickButton(config);
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
      model: providerChoice === "deepseek" && $("modelPreset").value !== "custom" ?
        $("modelPreset").value : $("modelId").value.trim(),
      base_url: providerChoice === "deepseek" ? "https://api.deepseek.com" : $("modelBaseUrl").value.trim(),
      reasoning_effort: providerChoice === "deepseek" ? $("modelReasoningEffort").value : null,
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
      const connection = data.connection || {};
      status.textContent = connection.status === "connected" ?
        "Подключено: DeepSeek · " + (connection.model || payload.model) +
          " · API-ключ проверен, следующие запросы используют эту модель" :
        connection.status === "not_checked" ?
          "Настройки применены, но совместимый API не подтвердил доступность модели" :
          "Применено: " + (data.settings?.model || payload.model) +
            " · следующие запросы используют эту модель";
      const title = $("modelName");
      if (title && stateModeIsResearcher()) title.textContent = data.settings?.model || payload.model;
      updateQuickButton(data.settings || {});
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

  function init() {
    ensurePanel();
    $("profileTabs")?.addEventListener("click", event => {
      const tab = event.target.closest("[data-profile-tab]");
      if (tab?.dataset.profileTab === "model") void loadModelConfig();
    });
    window.addEventListener("cybernova:open-model-settings", () => void loadModelConfig());
    void loadModelConfig();
  }
  document.addEventListener("DOMContentLoaded", init);
})();