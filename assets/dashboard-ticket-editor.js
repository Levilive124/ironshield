(() => {
  const root = document.getElementById('ticket-editor-root');
  const form = document.getElementById('ticket-settings-form');
  const dataNode = document.getElementById('ticket-settings-data');
  if (!root || !form || !dataNode) return;

  const html = (value) => String(value ?? '');
  const idPattern = /^\d{15,22}$/;
  // Preserve Discord snowflakes exactly: JSON.parse normally rounds these in JS.
  const raw = dataNode.textContent.replace(/(?<![\w"])(\d{15,22})(?![\w"])/g, '"$1"');
  let settings;
  try { settings = JSON.parse(raw); } catch { const error = document.createElement('p'); error.className = 'dashboard-message'; error.textContent = 'Die Ticket-Einstellungen konnten nicht gelesen werden.'; root.replaceChildren(error); return; }
  settings.guild ||= {};
  settings.panels ||= {};
  const originalPanelIds = Object.keys(settings.panels);
  const guildId = root.dataset.guild;
  const status = document.getElementById('ticket-option-status');
  let options = {channels: [], categories: [], roles: []};

  const el = (tag, attrs = {}, children = []) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key.startsWith('data-')) node.setAttribute(key, value);
      else if (key === 'html') node.textContent = value;
      else if (value !== undefined && value !== null) node.setAttribute(key, value);
    }
    for (const child of children) if (child) node.append(child);
    return node;
  };
  const section = (title, description = '') => {
    const box = el('section', {class:'ticket-editor-section'});
    box.append(el('div', {class:'ticket-editor-section-head'}, [el('h3', {text:title})]));
    if (description) box.append(el('p', {class:'ticket-editor-help', text:description}));
    const grid = el('div', {class:'ticket-editor-grid'});
    box.append(grid);
    return {box, grid};
  };
  const field = (label, key, value, type = 'text', attrs = {}) => {
    const wrap = el('label', {class:'ticket-editor-field'});
    wrap.append(el('span', {class:'ticket-editor-label', text:label}));
    let control;
    if (type === 'toggle') {
      control = el('input', {type:'checkbox', class:'ticket-editor-toggle', 'data-setting':key});
      control.checked = Boolean(value);
      wrap.classList.add('ticket-editor-switch');
      wrap.append(control, el('span', {class:'ticket-editor-switch-ui', 'aria-hidden':'true'}));
      return wrap;
    }
    if (type === 'textarea') {
      control = el('textarea', {class:'portal-textarea', rows:attrs.rows || 3, placeholder:attrs.placeholder || '', 'data-setting':key});
      control.value = value ?? '';
    } else if (type === 'select') {
      control = el('select', {class:'portal-select', 'data-setting':key, 'data-options':attrs.options || '', 'data-nullable':attrs.nullable ? '1' : '0'});
      control.append(el('option', {value:'', text:attrs.emptyLabel || 'Nicht festgelegt'}));
      const source = attrs.options === 'roles' ? options.roles : attrs.options === 'categories' ? options.categories : options.channels;
      const selectedValues = attrs.multiple && Array.isArray(value) ? value.map(String) : [String(value ?? '')];
      for (const option of source) {
        const choice = el('option', {value:option.id, text:(attrs.options === 'channels' && option.type === 5 ? '# ' : '') + option.name});
        if (selectedValues.includes(String(option.id))) choice.selected = true;
        control.append(choice);
      }
      for (const missing of selectedValues.filter(id => id && !source.some(item => String(item.id) === id))) control.append(el('option', {value:missing, text:'Gespeicherte Auswahl (' + missing + ')', selected:'selected'}));
      if (attrs.multiple) { control.multiple = true; control.size = Math.min(5, Math.max(3, source.length)); }
    } else {
      control = el('input', {type:type === 'number' ? 'number' : 'text', class:'portal-input', value:value ?? '', placeholder:attrs.placeholder || '', min:attrs.min, max:attrs.max, step:attrs.step, 'data-setting':key, 'data-value-type':type});
    }
    if (attrs.wide) wrap.classList.add('ticket-editor-wide');
    wrap.append(control);
    return wrap;
  };
  const add = (grid, label, key, value, type, attrs) => grid.append(field(label, key, value, type, attrs));

  function listEditor(label, key, values, placeholder = 'Eintrag hinzufügen', objectMode = false) {
    const wrap = el('div', {class:'ticket-editor-list ticket-editor-wide'});
    const top = el('div', {class:'ticket-editor-list-head'});
    top.append(el('span', {class:'ticket-editor-label', text:label}));
    const rows = el('div', {class:'ticket-editor-list-rows'});
    const draw = (value = '') => {
      const row = el('div', {class:'ticket-editor-list-row'});
      if (objectMode) {
        row.append(el('input', {class:'portal-input', placeholder:'Button-Text', value:value?.label || '', 'data-list-prop':'label'}));
        row.append(el('textarea', {class:'portal-textarea', rows:'2', placeholder:'Antworttext', 'data-list-prop':'text'}));
        row.lastChild.value = value?.text || '';
      } else row.append(el('input', {class:'portal-input', placeholder, value:typeof value === 'string' ? value : '', 'data-list-value':'1'}));
      const remove = el('button', {type:'button', class:'ticket-editor-remove', 'aria-label':'Eintrag entfernen', text:'Entfernen'});
      remove.addEventListener('click', () => row.remove());
      row.append(remove);
      rows.append(row);
    };
    for (const value of values || []) draw(value);
    const button = el('button', {type:'button', class:'button button-outline ticket-editor-add', text:'+ Hinzufügen'});
    button.addEventListener('click', () => draw());
    top.append(button);
    wrap.append(top, rows);
    if (objectMode) wrap.dataset.objectList = key;
    else wrap.dataset.listSetting = key;
    return wrap;
  }

  function mapEditor(label, key, values, valueLabel = 'Wert') {
    const wrap = el('div', {class:'ticket-editor-list ticket-editor-wide'});
    const top = el('div', {class:'ticket-editor-list-head'});
    top.append(el('span', {class:'ticket-editor-label', text:label}));
    const rows = el('div', {class:'ticket-editor-list-rows'});
    const draw = (name = '', value = '') => {
      const row = el('div', {class:'ticket-editor-list-row ticket-editor-map-row'});
      row.append(el('input', {class:'portal-input', placeholder:'Bereich / Stichwort', value:name, 'data-map-key':'1'}));
      row.append(el('input', {class:'portal-input', placeholder:valueLabel, value:value ?? '', 'data-map-value':'1'}));
      const remove = el('button', {type:'button', class:'ticket-editor-remove', text:'Entfernen'});
      remove.addEventListener('click', () => row.remove());
      row.append(remove); rows.append(row);
    };
    Object.entries(values || {}).forEach(([name,value]) => draw(name,value));
    const button = el('button', {type:'button', class:'button button-outline ticket-editor-add', text:'+ Regel hinzufügen'});
    button.addEventListener('click', () => draw());
    top.append(button); wrap.append(top, rows); wrap.dataset.mapSetting = key;
    return wrap;
  }

  function fieldset(title, children, removable = false, panelId = '', opened = false) {
    const details = el('details', {class:'ticket-panel-card'});
    details.open = opened;
    const summary = el('summary', {class:'ticket-panel-summary'});
    summary.append(el('strong', {text:title}));
    if (removable) {
      const remove = el('button', {type:'button', class:'ticket-editor-remove', text:'Panel löschen'});
      remove.addEventListener('click', (event) => { event.preventDefault(); event.stopPropagation(); if (confirm('Dieses Ticket-Panel wirklich löschen?')) details.remove(); });
      summary.append(remove);
    }
    details.append(summary, ...children);
    details.dataset.panelId = panelId;
    return details;
  }

  function render() {
    root.replaceChildren();
    const g = settings.guild;
    const guildSection = section('Serverweite Einstellungen', 'Rollen, Protokoll und allgemeine Ticket-Funktionen.');
    add(guildSection.grid, 'Support-Rollen', 'support_roles', g.support_roles || [], 'select', {options:'roles',multiple:true});
    add(guildSection.grid, 'Ausgeschlossene Rollen', 'blocked_roles', g.blocked_roles || [], 'select', {options:'roles',multiple:true});
    add(guildSection.grid, 'Serverweiter Protokoll-Kanal', 'log_channel', g.log_channel, 'select', {options:'channels',nullable:true});
    add(guildSection.grid, 'Ticket-Tags aktivieren', 'tags_enabled', g.tags_enabled, 'toggle');
    add(guildSection.grid, 'Archivierung aktivieren', 'archive_enabled', g.archive_enabled, 'toggle');
    add(guildSection.grid, 'Nutzer-Verlauf aktivieren', 'user_history_enabled', g.user_history_enabled, 'toggle');
    add(guildSection.grid, 'Geschäftszeiten aktivieren', 'business_hours_enabled', g.business_hours_enabled, 'toggle');
    add(guildSection.grid, 'Zeitzone', 'business_hours_tz', g.business_hours_tz || 'Europe/Berlin');
    add(guildSection.grid, 'Archiv-Kategorien', 'archive_categories', g.archive_categories || [], 'select', {options:'categories',multiple:true});
    guildSection.box.append(listEditor('Verfügbare Ticket-Tags', 'tags', g.tags || [], 'Tag-Name'));
    const hours = g.business_hours || {};
    const hoursWrap = el('div', {class:'ticket-editor-list ticket-editor-wide'});
    hoursWrap.append(el('span', {class:'ticket-editor-label', text:'Geschäftszeiten (Montag bis Sonntag)'}));
    const dayRows = el('div', {class:'ticket-editor-hours'});
    ['Montag','Dienstag','Mittwoch','Donnerstag','Freitag','Samstag','Sonntag'].forEach((day,index) => {
      const row = el('label', {class:'ticket-hours-row'}); const cfg = hours[String(index)] || {};
      row.append(el('span', {text:day}), el('input', {type:'checkbox', 'data-hour-open':String(index)}), el('input', {type:'time', value:cfg.start || '09:00', 'data-hour-start':String(index)}), el('span', {text:'bis'}), el('input', {type:'time', value:cfg.end || '17:00', 'data-hour-end':String(index)}));
      row.querySelector('[data-hour-open]').checked = Boolean(cfg.start && cfg.end); dayRows.append(row);
    });
    hoursWrap.append(dayRows); guildSection.box.append(hoursWrap); root.append(guildSection.box);

    const panelHead = el('div', {class:'ticket-editor-panel-head'});
    panelHead.append(el('div', {}, [el('h3', {text:'Ticket-Panels'}), el('p', {class:'ticket-editor-help', text:'Jedes Panel steuert einen eigenen Ticket-Einstieg.'})]));
    const addPanel = el('button', {type:'button', class:'button button-outline', text:'+ Panel hinzufügen'});
    panelHead.append(addPanel); root.append(panelHead);
    const panelsRoot = el('div', {class:'ticket-editor-panels'}); root.append(panelsRoot);

    function renderPanel(id, panel, fresh = false) {
      const p = panel || {};
      const block = el('div', {class:'ticket-editor-panel', 'data-panel':id});
      const basics = section('Panel und Ticket-Kanäle', 'Wähle, wo das Panel erscheint und wo neue Tickets angelegt werden.');
      add(basics.grid, 'Interner Panel-Name', 'name', p.name || 'Support');
      add(basics.grid, 'Überschrift im Panel', 'panel_title', p.panel_title || 'Support-Tickets');
      add(basics.grid, 'Panel-Text', 'panel_text', p.panel_text || '', 'textarea', {wide:true,placeholder:'Erkläre kurz, wie man hier ein Ticket erstellt.'});
      add(basics.grid, 'Panel-Kanal', 'channel', p.channel, 'select', {options:'channels',nullable:true});
      add(basics.grid, 'Ticket-Kategorie', 'category', p.category, 'select', {options:'categories',nullable:true});
      add(basics.grid, 'Protokoll-Kanal (leer = Serverstandard)', 'log_channel', p.log_channel, 'select', {options:'channels',nullable:true});
      add(basics.grid, 'Bewertungs-Kanal', 'rating_channel', p.rating_channel, 'select', {options:'channels',nullable:true});
      add(basics.grid, 'Panel-Bild-URL', 'image', p.image || '', 'text', {placeholder:'https://…'});
      add(basics.grid, 'Ticket-Kanal-Präfix', 'channel_prefix', p.channel_prefix || '', 'text', {placeholder:'ticket'});
      block.append(basics.box);

      const reasons = section('Ticket-Gründe und Ticket-Formular', 'Die Ticket-Gründe erscheinen beim Öffnen des Panels. Formularfragen können bis zu fünf Einträge enthalten.');
      block.append(reasons.box, listEditor('Ticket-Gründe', 'reasons', p.reasons || [], 'z. B. Allgemeine Frage'), listEditor('Fragen beim Öffnen', 'intake_questions', p.intake_questions || [], 'Frage eingeben'));
      add(reasons.grid, 'Formularfragen aktivieren', 'intake_enabled', p.intake_enabled, 'toggle');
      add(reasons.grid, 'Eigene Abschlussgründe aktivieren', 'close_reasons_enabled', p.close_reasons_enabled, 'toggle');
      block.append(listEditor('Abschlussgründe', 'close_reasons', p.close_reasons || [], 'z. B. Erledigt'));

      const features = section('Automatik und Fristen', 'Optionale Erinnerungen, Limits und automatische Abläufe.');
      add(features.grid, 'Cooldown aktivieren', 'cooldown_enabled', p.cooldown_enabled, 'toggle');
      add(features.grid, 'Cooldown (Sekunden)', 'cooldown_seconds', p.cooldown_seconds, 'number', {min:0,step:1});
      add(features.grid, 'Auto-Close nach (Stunden)', 'auto_close.hours', p.auto_close?.hours, 'number', {min:0,step:1});
      add(features.grid, 'SLA-Warnung nach (Minuten)', 'sla.minutes', p.sla?.minutes, 'number', {min:0,step:1});
      add(features.grid, 'SLA-Rolle', 'sla.role', p.sla?.role, 'select', {options:'roles',nullable:true});
      add(features.grid, 'Erinnerungen aktivieren', 'reminder_enabled', p.reminder_enabled, 'toggle');
      add(features.grid, 'Erinnerung nach (Minuten)', 'reminder_minutes', p.reminder_minutes, 'number', {min:0,step:1});
      add(features.grid, 'Eskalation aktivieren', 'escalation_enabled', p.escalation_enabled, 'toggle');
      add(features.grid, 'Eskalation nach (Minuten)', 'escalation.minutes', p.escalation?.minutes, 'number', {min:0,step:1});
      add(features.grid, 'Eskalations-Rolle', 'escalation.role', p.escalation?.role, 'select', {options:'roles',nullable:true});
      add(features.grid, 'Priorität bei Eskalation erhöhen', 'escalation.raise_priority', p.escalation?.raise_priority, 'toggle');
      add(features.grid, 'Auto-Tags aktivieren', 'auto_tag_enabled', p.auto_tag_enabled, 'toggle');
      add(features.grid, 'KI-Steuerung im Ticket aktivieren', 'ai_actions_enabled', p.ai_actions_enabled, 'toggle');
      block.append(features.box);

      const ai = section('KI-Antworten und Design', 'Passe Antworten, Ticket-Karten und sichtbare Schaltflächen an.');
      add(ai.grid, 'KI-Antworten aktivieren', 'ai_chat.enabled', p.ai_chat?.enabled, 'toggle');
      add(ai.grid, 'KI-Anweisung', 'ai_chat.prompt', p.ai_chat?.prompt || '', 'textarea', {wide:true,placeholder:'Wie soll die KI im Ticket antworten?'});
      add(ai.grid, 'Akzentfarbe', 'style.accent_mode', p.style?.accent_mode || 'priority', 'choice', {choices:[['priority','Nach Priorität'],['status','Nach Status'],['fixed','Feste Farbe']]});
      add(ai.grid, 'Feste Akzentfarbe (Hex)', 'style.accent_hex', p.style?.accent_hex || '', 'text', {placeholder:'#a5e58b'});
      add(ai.grid, 'Kompakte Ticket-Karte', 'style.compact', p.style?.compact, 'toggle');
      add(ai.grid, 'Avatar anzeigen', 'style.show_avatar', p.style?.show_avatar, 'toggle');
      block.append(ai.box);
      const replies = section('Schnellantworten', 'Textbausteine, die das Team direkt im Ticket nutzen kann.');
      block.append(replies.box, listEditor('Antworten', 'quick_replies', p.quick_replies || [], '', true));

      const mappings = section('Regeln pro Ticket-Grund', 'Lege Limits, Prioritäten, Begrüßungen und Stichwort-Regeln fest.');
      block.append(mappings.box);
      block.append(mapEditor('Maximal offene Tickets je Grund', 'limits', p.limits, 'Anzahl'));
      block.append(mapEditor('Start-Priorität je Grund', 'reason_priority', p.reason_priority, 'Priorität'));
      block.append(mapEditor('Emoji je Grund', 'reason_emoji', p.reason_emoji, 'Emoji'));
      block.append(mapEditor('Begrüßung je Grund', 'reason_greeting', p.reason_greeting, 'Text'));
      block.append(mapEditor('Stichwort → Priorität', 'keyword_priority', p.keyword_priority, 'Priorität'));
      block.append(mapEditor('Stichwort → Tag', 'tag_keywords', p.tag_keywords, 'Tag'));
      add(mappings.grid, 'Stichwort-Priorität aktivieren', 'keyword_priority_enabled', p.keyword_priority_enabled, 'toggle');

      const buttons = section('Schaltflächen im geöffneten Ticket', 'Wähle, welche Werkzeuge das Team im Ticket sieht.');
      const buttonNames = {claim:'Übernehmen',users:'Nutzer verwalten',notes:'Notizen',ai_summary:'KI-Zusammenfassung',close_request:'Schließanfrage',handoff:'Weitergeben',priority:'Priorität ändern',quick_reply:'Schnellantwort',tags:'Tags',snooze:'Zurückstellen',link:'Ticket verknüpfen'};
      for (const [key,label] of Object.entries(buttonNames)) add(buttons.grid, label, 'buttons.' + key, p.buttons?.[key] !== false, 'toggle');
      block.append(buttons.box);
      const title = p.name || p.panel_title || ('Panel ' + id);
      const hasOpenPanel = Boolean(panelsRoot.querySelector('details[open]'));
      panelsRoot.append(fieldset(title, [block], !fresh, id, fresh || !hasOpenPanel));
    }
    for (const [id,p] of Object.entries(settings.panels)) renderPanel(id,p);
    if (!Object.keys(settings.panels).length) renderPanel('default', {}, false, true);
    addPanel.addEventListener('click', () => {
      if (panelsRoot.querySelectorAll('[data-panel]').length >= 25) { alert('Discord erlaubt höchstens 25 Ticket-Panels.'); return; }
      const id = 'web_' + Math.random().toString(36).slice(2, 10);
      settings.panels[id] = {name:'Neues Panel',panel_title:'Support-Tickets',panel_text:'Wähle einen Grund aus und beschreibe dein Anliegen.',channel:null,category:null,reasons:[],log_channel:null,limits:{},reason_priority:{},image:null,ai_chat:{enabled:false,prompt:''},sla:{minutes:null,role:null},rating_channel:null,quick_replies:[],auto_close:{hours:null},style:{accent_mode:'priority',accent_hex:null,compact:false,show_avatar:true},channel_prefix:null,reason_emoji:{},reason_greeting:{},close_reasons:[],close_reasons_enabled:false,intake_questions:[],intake_enabled:false,cooldown_seconds:null,cooldown_enabled:false,keyword_priority:{},keyword_priority_enabled:false,reminder_minutes:null,reminder_enabled:false,buttons:{},escalation_enabled:false,escalation:{},auto_tag_enabled:false,tag_keywords:{},ai_actions_enabled:false};
      renderPanel(id, settings.panels[id], true);
      makeChoiceFields();
    });
  }

  function makeChoiceFields() {
    root.querySelectorAll('[data-setting="style.accent_mode"]').forEach(input => {
      const select = el('select', {class:'portal-select', 'data-setting':'style.accent_mode'});
      [['priority','Nach Priorität'],['status','Nach Status'],['fixed','Feste Farbe']].forEach(([value,label]) => { const option=el('option',{value,text:label}); if (value === input.value) option.selected=true; select.append(option); });
      input.replaceWith(select);
    });
  }
  function fillDiscordSelects() {
    root.querySelectorAll('select[data-options]').forEach(select => {
      const selected = select.multiple ? [...select.selectedOptions].map(option=>option.value) : [select.value];
      const source = select.dataset.options === 'roles' ? options.roles : select.dataset.options === 'categories' ? options.categories : options.channels;
      const empty = select.multiple ? null : select.options[0]; select.replaceChildren(); if (empty) select.append(empty);
      for (const option of source) { const item=el('option',{value:option.id,text:(select.dataset.options==='channels'&&option.type===5?'# ':'')+option.name}); if(selected.includes(String(option.id)))item.selected=true; select.append(item); }
      for (const id of selected.filter(Boolean)) if (!source.some(option=>String(option.id)===String(id))) select.append(el('option',{value:id,text:'Gespeicherte Auswahl ('+id+')',selected:'selected'}));
    });
  }
  function readPath(object, path) { const parts=path.split('.'); const last=parts.pop(); let target=object; for(const part of parts) target=target[part] ||= {}; return [target,last]; }
  function numericOrNull(value) { if (value === '') return null; const number=Number(value); return Number.isFinite(number) ? Math.trunc(number) : null; }
  function collect() {
    const next = JSON.parse(JSON.stringify(settings));
    next.guild ||= {}; next.panels ||= {};
    for (const control of root.querySelectorAll('[data-setting]')) {
      const panel = control.closest('[data-panel]');
      const target = panel ? (next.panels[panel.dataset.panel] ||= {}) : next.guild;
      const [parent,key] = readPath(target, control.dataset.setting);
      let value;
      if (control.type === 'checkbox') value=control.checked;
      else if (control.multiple) value=[...control.selectedOptions].map(option=>option.value).filter(Boolean);
      else if (control.tagName === 'SELECT' && control.dataset.options) value=control.value === '' ? null : control.value;
      else if (control.type === 'number') value=numericOrNull(control.value);
      else value=control.value;
      if (control.multiple && ['support_roles','blocked_roles','archive_categories'].includes(key)) value=value.filter(idPattern.test.bind(idPattern));
      parent[key]=value;
    }
    for (const list of root.querySelectorAll('[data-list-setting]')) {
      const panel=list.closest('[data-panel]'); const target=panel ? (next.panels[panel.dataset.panel] ||= {}) : next.guild;
      const key=list.dataset.listSetting;
      const values=[...list.querySelectorAll('.ticket-editor-list-row')].map(row=>row.querySelector('[data-list-value]')?.value.trim() ?? '').filter(Boolean);
      const [parent,last]=readPath(target,key); parent[last]=values;
    }
    for (const list of root.querySelectorAll('[data-object-list]')) {
      const panel=list.closest('[data-panel]'); const target=next.panels[panel.dataset.panel] ||= {};
      target[list.dataset.objectList]=[...list.querySelectorAll('.ticket-editor-list-row')].map(row=>({label:row.querySelector('[data-list-prop="label"]').value.trim(),text:row.querySelector('[data-list-prop="text"]').value.trim()})).filter(row=>row.label||row.text);
    }
    for (const list of root.querySelectorAll('[data-map-setting]')) {
      const panel=list.closest('[data-panel]'); const target=next.panels[panel.dataset.panel] ||= {}; const map={};
      for(const row of list.querySelectorAll('.ticket-editor-list-row')) { const key=row.querySelector('[data-map-key]').value.trim(); const rawValue=row.querySelector('[data-map-value]').value.trim(); if(!key||!rawValue)continue; map[key]=['limits','reason_priority','keyword_priority'].includes(list.dataset.mapSetting) ? (Number.isFinite(Number(rawValue))?Math.trunc(Number(rawValue)):rawValue) : rawValue; }
      target[list.dataset.mapSetting]=map;
    }
    const hours={}; root.querySelectorAll('[data-hour-open]').forEach(open=>{const day=open.dataset.hourOpen;if(open.checked)hours[day]={start:root.querySelector(`[data-hour-start="${day}"]`).value,end:root.querySelector(`[data-hour-end="${day}"]`).value};});
    next.guild.business_hours=hours;
    const visible=new Set([...root.querySelectorAll('[data-panel]')].map(panel=>panel.dataset.panel));
    for(const id of Object.keys(next.panels)) if(!visible.has(id)) delete next.panels[id];
    next.delete_panels=(settings.delete_panels||[]).filter(id=>originalPanelIds.includes(id)&&!visible.has(id));
    for(const id of originalPanelIds) if(!visible.has(id)&&!next.delete_panels.includes(id))next.delete_panels.push(id);
    return next;
  }
  function stringifyExact(value) {
    const marked=(node)=>{
      if(Array.isArray(node))return node.map(marked);
      if(node&&typeof node==='object'){for(const key of Object.keys(node))node[key]=marked(node[key]);return node;}
      return typeof node==='string'&&idPattern.test(node)?`__IRONSHIELD_SNOWFLAKE_${node}__`:node;
    };
    return JSON.stringify(marked(value)).replace(/"__IRONSHIELD_SNOWFLAKE_(\d{15,22})__"/g,'$1');
  }
  form.addEventListener('submit', event => {
    const output=document.getElementById('ticket-settings-json');
    try { output.value=stringifyExact(collect()); }
    catch(error) { event.preventDefault(); alert('Einstellungen konnten nicht vorbereitet werden: '+error.message); }
  });

  render(); makeChoiceFields();
  fetch('/index.php?route=dashboard_options&guild='+encodeURIComponent(guildId), {credentials:'same-origin',headers:{Accept:'application/json'},cache:'no-store'})
    .then(response=>response.ok?response.json():Promise.reject(new Error('Discord-Auswahl nicht verfügbar')))
    .then(data=>{options=data;fillDiscordSelects();if(status)status.textContent='Discord-Kanäle und Rollen geladen';})
    .catch(()=>{if(status)status.textContent='Discord-Auswahl nicht geladen. Bereits gespeicherte Werte bleiben erhalten.';});
})();
