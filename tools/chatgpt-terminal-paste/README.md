# Cybernova — Send terminal output to ChatGPT

A tiny unpacked Chrome/Chromium extension for the exact workflow:

1. Select terminal output and copy it.
2. Return to the open ChatGPT conversation.
3. Right-click **inside the message input**.
4. The extension reads the clipboard, inserts the text, and clicks Send.

No extra menu click is required. Right-click outside the ChatGPT message field keeps the browser's normal context menu.

## Install in Chrome

1. Download this folder or the repository ZIP and extract it.
2. Open `chrome://extensions`.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the `tools/chatgpt-terminal-paste` folder.
6. Reload the ChatGPT tab.

For Microsoft Edge, use `edge://extensions` and the same steps.

## Safety and scope

- Runs only on `chatgpt.com` and the legacy `chat.openai.com` domain.
- Reads clipboard text only after a right-click inside the ChatGPT message field.
- Sends plain text only; no files, images, passwords store, or background clipboard polling.
- Makes no network requests and uses no remote scripts or third-party libraries.
- Does not store clipboard contents.
- If the ChatGPT composer already contains a draft, it refuses to send so the draft is not mixed with terminal output.
- Clipboard text over 100,000 characters is rejected.
- If the send button is unavailable, text remains in the composer for manual review.

Chrome displays a clipboard permission warning because the extension needs to read copied terminal output. Its code only invokes clipboard access in the explicit right-click handler described above.

## Behavior

Right-click **inside the ChatGPT message field** = paste clipboard text and send it.

Right-click elsewhere = normal browser context menu.
