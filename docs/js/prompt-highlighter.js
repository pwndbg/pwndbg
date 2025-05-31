document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('pre > code').forEach(codeBlock => {
    const lines = codeBlock.textContent.split('\n');

    const newHtml = lines.map(line => {
      const match = line.match(/^(pwndbg>|>)(.*)/);
      if (match) {
        const prompt = match[1];
        const rest = match[2];
        return `<div class="code-line"><span class="pwndbg-prompt">${prompt}</span><span class="pwndbg-cmd">${rest}</span></div>`;
      } else {
        return line
      }
    }).join('<br>');

    codeBlock.innerHTML = newHtml;
  });
});
