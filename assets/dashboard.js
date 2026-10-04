(() => {
  const content = document.getElementById('dashboard-content');
  const connection = document.getElementById('dashboard-connection');
  const connectionTitle = document.getElementById('dashboard-connection-title');
  const connectionDetail = document.getElementById('dashboard-connection-detail');
  const message = document.getElementById('dashboard-message');
  const params = new URLSearchParams(location.search);
  const guildId = params.get('guild') || '';
  let lastSeen = 0;
  let current = null;
  let syncing = false;

  const node = (tag, className, text) => {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  };
  const link = (href, className, text, newTab = false) => {
    const item = node('a', className, text);
    item.href = href;
    if (newTab) { item.target = '_blank'; item.rel = 'noopener noreferrer'; }
    return item;
  };
  const showMessage = (text, error = false) => {
    message.hidden = !text;
    message.textContent = text || '';
    message.classList.toggle('is-error', error);
  };
  async function readApiJson(response) {
    if (!(response.headers.get('content-type') || '').toLowerCase().includes('application/json')) {
      const contentType = response.headers.get('content-type') || 'unbekannt';
      const finalUrl = new URL(response.url).pathname;
      let detail = '';
      try {
        const body = await response.clone().text();
        const title = body.match(/<title[^>]*>(.*?)<\/title>/is)?.[1]?.replace(/\s+/g, ' ').trim();
        if (title) detail = ` Antwortseite: ${title.slice(0, 100)}.`;
      } catch { /* Keep the routing hint even when the body cannot be read. */ }
      throw new Error(`Dashboard-API lieferte kein JSON (HTTP ${response.status}, ${contentType}, ${finalUrl}). Vercel liefert hier eine Webseite statt der PHP-API.${detail}`);
    }
    try { return await response.json(); }
    catch { throw new Error(`Dashboard-API lieferte ungültiges JSON (HTTP ${response.status}).`); }
  }
  function renderConnection(data) {
    const online = Boolean(data.connected);
    connection.classList.toggle('is-online', online);
    connection.classList.toggle('is-offline', !online);
    connectionTitle.textContent = online ? 'Bot verbunden' : 'Warte auf Bot-Verbindung';
    if (data.last_seen) lastSeen = Math.max(lastSeen, Number(data.last_seen));
    connectionDetail.textContent = lastSeen ? `Letzter Abgleich vor ${Math.max(0, Math.floor(Date.now() / 1000) - lastSeen)} Sekunden` : 'Noch keine Verbindung gemeldet';
  }
  async function requestState() {
    const response = await fetch(`/api/index.php?route=dashboard_data${guildId ? `&guild=${encodeURIComponent(guildId)}` : ''}`, {credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
    const data = await readApiJson(response);
    if (response.status === 401) { location.assign('/api/index.php?route=dashboard_login'); return null; }
    if (!response.ok) throw new Error(data.error || 'Dashboard-Daten konnten nicht geladen werden.');
    return data;
  }
  async function refreshBot() {
    if (syncing || document.hidden) return;
    syncing = true;
    try {
      const query = guildId ? `&guild=${encodeURIComponent(guildId)}` : '';
      const response = await fetch(`/api/index.php?route=dashboard_refresh${query}`, {credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
      const state = await readApiJson(response);
      if (!response.ok) throw new Error(state.error || 'Bot-Status kann gerade nicht aktualisiert werden.');
      if (state.connection_error || state.error) showMessage(state.connection_error || state.error, true);
      else if (state.relay_refresh_needed) showMessage('Warte auf die Bot-Synchronisierung. Prüfe PUBLIC_SITE_URL und den Bridge-Schlüssel in den Hosting-Umgebungen.');
      const updated = await requestState();
      if (updated) {
        const shouldRefreshSelected = guildId && updated.selected && current?.selected
          && ((!current.selected.checked && updated.selected.checked)
            || (!current.ticket_settings && Boolean(updated.ticket_settings)));
        current = updated;
        renderConnection(updated);
        if (shouldRefreshSelected && !content.querySelector('#ticket-settings-form[data-dirty="1"]')) renderManage(updated);
        else renderStatusOnly(updated);
      }
    } catch (error) {
      showMessage(error.message || 'Bot-Status kann gerade nicht aktualisiert werden.', true);
    } finally { syncing = false; }
  }
  function renderStatusOnly(data) {
    for (const card of content.querySelectorAll('[data-guild-card]')) {
      const status = data.guilds.find(item => item.id === card.dataset.guildCard);
      if (!status) continue;
      const text = card.querySelector('.guild-status');
      if (text) {
        text.textContent = status.present ? 'Bot ist auf diesem Server' : status.checked ? 'Bot ist noch nicht eingeladen' : 'Bot-Status wird ermittelt';
        text.classList.toggle('is-present', status.present);
      }
    }
  }
  function renderList(data) {
    content.replaceChildren();
    const toolbar = node('div','guild-toolbar',`${data.guilds.length} Server, auf denen du Mitglied bist`);
    content.append(toolbar);
    const grid = node('div','guild-grid');
    for (const guild of data.guilds) {
      const card = node('article','guild-card');
      card.dataset.guildCard = guild.id;
      const isInvite = guild.checked && !guild.present && guild.manage;
      const target = isInvite ? `${data.invite_base}&guild_id=${encodeURIComponent(guild.id)}&disable_guild_select=true` : `/dashboard.html?guild=${encodeURIComponent(guild.id)}`;
      const anchor = link(target,'guild-open guild-card-link',undefined,isInvite);
      anchor.dataset.guildLink = '';
      const icon = node('div','guild-icon');
      if (guild.icon) { const image = node('img'); image.src = guild.icon; image.alt = ''; image.loading = 'lazy'; image.decoding = 'async'; icon.append(image); }
      else icon.textContent = (guild.name.trim().slice(0,1) || '?').toUpperCase();
      const details = node('div','guild-details');
      details.append(node('h3','',guild.name),node('p',`guild-status${guild.present ? ' is-present' : ''}`,guild.present ? 'Bot ist auf diesem Server' : guild.checked ? 'Bot ist noch nicht eingeladen' : 'Bot-Status wird ermittelt'));
      anchor.append(icon,details,node('span',`button ${isInvite ? 'button-outline' : 'button-primary'} guild-invite`,!guild.manage ? 'Server öffnen →' : guild.present ? 'Server verwalten · Ticketing einstellen →' : isInvite ? 'Bot einladen ↗' : 'Serverstatus prüfen →'));
      card.append(anchor); grid.append(card);
    }
    if (!data.guilds.length) grid.append(node('p','','Discord hat keine Server zurückgegeben. Bitte melde dich erneut über Discord an.'));
    content.append(grid);
  }
  function renderManage(data) {
    const guild = data.selected;
    const section = node('section','guild-dialog-content');
    section.append(node('p','').appendChild(link('/dashboard.html','dashboard-link','← Zur Serverübersicht')).parentElement);
    section.append(node('h2','',`${guild.name} verwalten`));
    if (!guild.manage) {
      section.append(node('p','','Du brauchst Admin- oder Serververwaltungsrechte, um die Einstellungen zu ändern.'));
    } else if (!guild.checked) {
      section.append(node('p','','Der Serverstatus wird von Discord geprüft. Die Seite aktualisiert die Prüfung im Hintergrund.'));
    } else if (!guild.present) {
      section.append(node('p','','Der Bot ist auf diesem Server noch nicht eingeladen.'));
      section.append(link(`${data.invite_base}&guild_id=${encodeURIComponent(guild.id)}&disable_guild_select=true`,'button button-primary','Bot einladen ↗',true));
    } else if (data.ticket_settings) {
      const layout = node('div','dashboard-manage-layout');
      const nav = node('nav','dashboard-manage-nav');
      nav.setAttribute('aria-label','Verwaltung');
      nav.append(node('span','dashboard-manage-nav-title','Verwaltung'));
      const navLink = node('a','dashboard-manage-nav-link is-active');
      navLink.href = '#ticketsystem'; navLink.setAttribute('aria-current','page');
      navLink.append(node('span','dashboard-manage-nav-icon','🎫'));
      const navCopy = node('span','dashboard-manage-nav-copy'); navCopy.append(node('strong','','Ticketsystem'),node('small','','Ticketing und Panels'));
      navLink.append(navCopy,node('span','dashboard-manage-nav-arrow','›'));
      nav.append(navLink,node('p','dashboard-manage-nav-note','Weitere Funktionen werden hier ergänzt.'));
      const body = node('div','dashboard-manage-content'); body.id='ticketsystem';
      body.append(node('p','','Stelle Ticketing direkt hier ein. Kanäle und Rollen werden aus Discord geladen; deine Änderungen werden mit dem Bot synchronisiert.'));
      const form = node('form','portal-card ticket-editor'); form.id='ticket-settings-form'; form.method='post'; form.action='/api/index.php?route=dashboard_tickets_save';
      form.addEventListener('input',()=>{form.dataset.dirty='1';});
      form.addEventListener('change',()=>{form.dataset.dirty='1';});
      const csrf = node('input'); csrf.type='hidden'; csrf.name='csrf'; csrf.value=data.csrf;
      const guildField = node('input'); guildField.type='hidden'; guildField.name='guild_id'; guildField.value=guild.id;
      const settings = node('input'); settings.type='hidden'; settings.name='settings'; settings.id='ticket-settings-json';
      const editorRoot = node('div'); editorRoot.id='ticket-editor-root'; editorRoot.dataset.guild=guild.id;
      const dataNode = node('script'); dataNode.type='application/json'; dataNode.id='ticket-settings-data'; dataNode.textContent=JSON.stringify(data.ticket_settings);
      const saveNote = node('p','portal-meta','Die Einstellungen werden an den Ticket-Cog gesendet. Offene Tickets und Statistiken bleiben geschützt.');
      const submitRow = node('div','ticket-editor-submit');
      submitRow.append(node('span','ticket-option-status','Discord-Auswahlen werden geladen…'));
      const save = node('button','button button-primary','Einstellungen speichern'); save.type='submit'; submitRow.append(save);
      form.append(csrf,guildField,settings,editorRoot,dataNode,saveNote,submitRow); body.append(form);
      layout.append(nav,body); section.append(layout);
      const editorScript = node('script'); editorScript.src='/assets/dashboard-ticket-editor.js'; editorScript.defer=true; document.body.append(editorScript);
    } else {
      section.append(node('p','','Der Bot ist auf diesem Server. Ticket-Einstellungen werden noch synchronisiert.'));
    }
    if (guild.manage) renderModules(section,data);
    content.replaceChildren(section);
  }
  function renderModules(section,data) {
    const wrap=node('section','dashboard-bot-modules');
    const head=node('div','dashboard-bot-modules-heading'); const copy=node('div');
    copy.append(node('h3','','Bot-Module'),node('p','','Module dieses Servers über die sichere Bot-Verbindung verwalten.'));
    head.append(copy); wrap.append(head);
    if (data.modules_error) wrap.append(node('p','dashboard-message is-error',`Bot-WebAPI-Verbindung fehlgeschlagen: ${data.modules_error}`));
    else if (!Array.isArray(data.modules?.categories)) wrap.append(node('p','dashboard-message is-error','Der Bot hat keine Modulübersicht geliefert.'));
    else for (const category of data.modules.categories) {
      const group=node('div','dashboard-bot-module-category');
      const label=typeof category.label==='object' ? category.label.de : category.label;
      group.append(node('h4','',label || 'Module'));
      const list=node('div','dashboard-bot-module-list');
      for (const module of category.modules || []) {
        if (!/^[a-z0-9_-]{1,80}$/.test(String(module.key || ''))) continue;
        const form=node('form','dashboard-bot-module-row'); form.method='post'; form.action='/api/index.php?route=dashboard_module_save';
        const addHidden=(name,value)=>{const input=node('input');input.type='hidden';input.name=name;input.value=value;form.append(input);};
        addHidden('csrf',data.csrf);addHidden('guild_id',data.selected.id);addHidden('module_key',module.key);addHidden('enabled','0');
        const labelNode=node('label','dashboard-bot-module-copy'); const text=node('span');
        const moduleLabel=typeof module.label==='object'?module.label.de:module.label;
        const moduleDescription=typeof module.desc==='object'?module.desc.de:module.desc;
        text.append(node('strong','',moduleLabel || module.key),node('small','',moduleDescription || ''));
        const check=node('input');check.type='checkbox';check.name='enabled';check.value='1';check.checked=Boolean(module.enabled);check.setAttribute('aria-label',`${moduleLabel || module.key} aktivieren`);
        labelNode.append(text,check);form.append(labelNode);
        const save=node('button','button button-outline','Speichern');save.type='submit';form.append(save);list.append(form);
      }
      group.append(list);wrap.append(group);
    }
    section.append(wrap);
  }
  function render(data) {
    current=data;
    document.getElementById('dashboard-user').textContent=data.user.username;
    const logoutCsrf = document.querySelector('.user-chip form [name="csrf"]');
    if (logoutCsrf) logoutCsrf.value = data.csrf;
    renderConnection(data);
    const error=data.connection_error || data.relay_error;
    if (error) showMessage(`Synchronisierungsfehler: ${error}`,true);
    if (guildId && data.selected) renderManage(data);
    else renderList(data);
  }
  async function load() {
    try {
      const data=await requestState();
      if (!data) return;
      render(data);
      if (!data.bot_token_verified || data.guilds.some(item=>!item.checked) || Date.now()/1000-Number(data.last_seen||0)>45) refreshBot();
    } catch(error) {
      if (error.message==='login_required') location.assign('/api/index.php?route=dashboard_login');
      else { showMessage(error.message,true); content.replaceChildren(); }
    }
  }
  setInterval(() => { if (lastSeen) connectionDetail.textContent=`Letzter Abgleich vor ${Math.max(0,Math.floor(Date.now()/1000)-lastSeen)} Sekunden`; },1000);
  setInterval(refreshBot,45000);
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)refreshBot();});
  load();
})();
