import { readFile, writeFile } from 'node:fs/promises';

const source = await readFile(new URL('../includes/recht.php', import.meta.url), 'utf8');
const pattern = /'(?<key>datenschutz|nutzungsbedingungen|impressum)'\s*=>\s*\[\s*'title'\s*=>\s*'(?<title>[^']*)',\s*'updated'\s*=>\s*'(?<updated>[^']*)',\s*'text'\s*=>\s*<<<'(?<tag>[A-Z]+)'\r?\n(?<body>[\s\S]*?)\r?\n\k<tag>,/g;
const docs = [...source.matchAll(pattern)];
if (docs.length !== 3) throw new Error(`Expected 3 legal documents, found ${docs.length}`);

const esc = (text) => text.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;');
function inline(text) {
  let html = esc(text).replace(/\*\*(.+?)\*\*/gu, '<strong>$1</strong>');
  html = html.replace(/https:\/\/[^\s<]+/gu, (raw) => {
    const url = raw.replace(/[.,;:)]+$/u, '');
    const tail = raw.slice(url.length);
    const safe = esc(url);
    return `<a href="${safe}" target="_blank" rel="noopener noreferrer">${safe}</a>${tail}`;
  });
  return html.replace(/(?<![\w"/])([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})/gu, '<a href="mailto:$1">$1</a>');
}
function render(text) {
  let html = '', listOpen = false, plainList = false, section = 0;
  const toc = [];
  for (const raw of text.trim().split(/\r?\n/u)) {
    const line = raw.trim();
    if (!line) { if (listOpen) { html += '</ul>'; listOpen = false; } plainList = false; continue; }
    if (line === 'Datenschutzerklärung' || line.startsWith('Zuletzt aktualisiert:')) continue;
    let level = 0, heading = '';
    let match = line.match(/^(#{2,3})\s+(.+)$/u);
    if (match) { level = match[1].length; heading = match[2]; }
    else if ((match = line.match(/^(\d+\.\s+.+)$/u))) { level = 2; heading = match[1]; }
    else if ((match = line.match(/^([a-d]\)\s+.+)$/iu))) { level = 3; heading = match[1]; }
    if (level) {
      if (listOpen) { html += '</ul>'; listOpen = false; }
      plainList = false;
      if (level === 2) {
        if (section) html += '</section>';
        section++;
        const id = `abschnitt-${section}`;
        toc.push({ id, title: heading });
        html += `<section class="legal-section"><h2 id="${id}">${inline(heading)}</h2>`;
      } else html += `<h3>${inline(heading)}</h3>`;
      continue;
    }
    if (line.startsWith('- ')) {
      if (!listOpen) { html += '<ul>'; listOpen = true; }
      html += `<li>${inline(line.slice(2))}</li>`;
      plainList = false;
      continue;
    }
    if (plainList && !/^(?:[a-d]\)|\d+\.)/u.test(line)) {
      if (!listOpen) { html += '<ul>'; listOpen = true; }
      html += `<li>${inline(line)}</li>`;
      continue;
    }
    if (listOpen) { html += '</ul>'; listOpen = false; }
    html += `<p>${inline(line)}</p>`;
    plainList = line.endsWith(':');
  }
  if (listOpen) html += '</ul>';
  if (section) html += '</section>';
  return { html, toc };
}
const pages = [
  ['datenschutz', 'Datenschutz'],
  ['nutzungsbedingungen', 'Nutzungsbedingungen'],
  ['impressum', 'Impressum'],
];
for (const doc of docs) {
  const { key, title, updated, body } = doc.groups;
  const { html, toc } = render(body);
  const nav = pages.map(([slug, label]) => `<a href="/${slug}.html">${label}</a>`).join('');
  const tocHtml = toc.length ? `<aside class="legal-toc"><span>AUF DIESER SEITE</span>${toc.map((item) => `<a href="#${item.id}">${esc(item.title)}</a>`).join('')}</aside>` : '';
  const updatedHtml = updated ? `<p>Zuletzt aktualisiert: ${esc(updated)}</p>` : '';
  const page = `<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#090c11"><title>${esc(title)} — Iron Shield</title><link rel="icon" type="image/webp" href="/assets/bot-logo.webp"><link rel="stylesheet" href="/assets/styles.css"></head>
<body class="legal-body"><header class="site-header legal-header"><a class="brand" href="/" aria-label="Iron Shield Startseite"><span class="brand-mark"><img src="/assets/bot-logo.webp" alt=""></span><span class="brand-name">IRON<span>SHIELD</span></span></a><nav class="legal-nav" aria-label="Rechtliche Informationen">${nav}</nav></header>
<main id="top" class="legal-main section-wrap"><div class="legal-hero"><div class="eyebrow"><span class="status-dot"></span> IRON SHIELD · RECHTLICHE INFORMATIONEN</div><h1>${esc(title)}<span>.</span></h1>${updatedHtml}</div><div class="legal-layout">${tocHtml}<article class="legal-content">${html}</article></div><a class="legal-back" href="/">← Zurück zu Iron Shield</a></main>
<footer class="site-footer section-wrap legal-footer"><a class="brand footer-brand" href="/"><span class="brand-mark"><img src="/assets/bot-logo.webp" alt=""></span><span class="brand-name">IRON<span>SHIELD</span></span></a><nav class="footer-legal">${nav}</nav><a class="back-top" href="#top">NACH OBEN <span>↑</span></a></footer></body></html>`;
  await writeFile(new URL(`../${key === 'datenschutz' ? 'datenschutz' : key}.html`, import.meta.url), page);
}
