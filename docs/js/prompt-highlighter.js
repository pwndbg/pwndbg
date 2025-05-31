function highlightPrompts() {
  document.querySelectorAll('pre > code').forEach(codeBlock => {
    if (codeBlock.dataset.promptProcessed) return;
    codeBlock.dataset.promptProcessed = 'true';

    // Match `pwndbg>` and `>`.
    const lines = codeBlock.querySelectorAll('span[id^="__span"]');

    lines.forEach(lineEl => {
      const text = lineEl.textContent;
      const match = text.match(/^(pwndbg>|>)(.*)/);
      if (match) {
        const prompt = match[1];
        const rest = match[2];

        lineEl.innerHTML = '';

        const promptSpan = document.createElement('span');
        promptSpan.className = 'pwndbg-prompt';
        promptSpan.textContent = prompt;

        const contentSpan = document.createElement('span');
        contentSpan.className = 'pwndbg-cmd';
        contentSpan.textContent = rest;

        lineEl.appendChild(promptSpan);
        lineEl.appendChild(contentSpan);
      }
    });
  });
}

// Initial run.
highlightPrompts();

const observer = new MutationObserver(() => {
  highlightPrompts();
});

// FIXME: Not the best thing for performance but can't figure
// out a better way.
// https://github.com/squidfunk/mkdocs-material/discussions/8240
observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
  attributes: true,
  characterData: true
});
