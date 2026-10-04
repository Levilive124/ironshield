(() => {
  const root = document.getElementById('portal-root');
  if (!root) return;
  const view = root.dataset.view;
  const query = new URLSearchParams(location.search);
  const ticketId = query.get('id') || '';
  let state = null;
  let messageCount = 0;
  let polling = false;

  const el = (tag, className = '', text) => {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  };
  const anchor = (href, className, text) => { const item=el('a',className,text);item.href=href;return item; };
  const hidden = (form,name,value) => { const input=el('input');input.type='hidden';input.name=name;input.value=value;form.append(input);return input; };
  const form = (className,action) => {const item=el('form',className);item.method='post';item.action=`/api/index.php?route=${action}`;return item;};
  const label = (title,control,extra='') => {const item=el('label','portal-label');item.append(document.createTextNode(title));if(extra)item.append(el('span','optional-label',extra));item.append(control);return item;};
  const input = (name,placeholder='',type='text',maxLength) => {const item=el('input','portal-input');item.name=name;item.type=type;item.placeholder=placeholder;if(maxLength)item.maxLength=maxLength;if(type==='text'||type==='password')item.required=true;return item;};
  const textarea = (name,placeholder,maxLength,compact=false) => {const item=el('textarea',`portal-textarea${compact?' compact-textarea':''}`);item.name=name;item.placeholder=placeholder;item.maxLength=maxLength;item.required=!compact;return item;};
  const button = (text,className='portal-button') => {const item=el('button',className,text);item.type='submit';return item;};
  const meta = (value) => new Date(Number(value||0)*1000).toLocaleString('de-DE',{dateStyle:'medium',timeStyle:'short'});
  const displayMessage = (text,error=false) => {if(!text)return;const box=el('div',`portal-flash${error?' is-error':''}`,text);root.prepend(box);};
  const categoryNames={security:'Sicherheit / Schutz',technical:'Technischer Support',bug:'Fehler melden',question:'Allgemeine Frage',other:'Sonstiges'};
  function attachmentNodes(ticketId,attachments) {
    const wrap=el('div','ticket-attachments');
    for(const item of attachments||[]) {
      if(!/^[a-f0-9]{40}$/.test(String(item.id||'')))continue;
      const url=`/api/index.php?route=ticket_attachment&id=${encodeURIComponent(ticketId)}&file=${encodeURIComponent(item.id)}`;
      const name=String(item.name||'Anhang');
      if(String(item.mime||'').startsWith('image/')) {const a=anchor(url,'ticket-attachment-image');a.setAttribute('aria-label',name);const img=el('img');img.src=url;img.alt=name;img.loading='lazy';a.append(img);wrap.append(a);}
      else if(String(item.mime||'').startsWith('video/')) {const video=el('video','ticket-attachment-video');video.controls=true;video.preload='none';const source=el('source');source.src=url;source.type=item.mime;video.append(source);wrap.append(video);}
      const file=anchor(url,'ticket-attachment-file',`↧ ${name} · ${((Number(item.size||0))/1048576).toLocaleString('de-DE',{maximumFractionDigits:1})} MB`);file.download=name;wrap.append(file);
    }
    return wrap;
  }
  function messageNode(ticketId,item) {
    const article=el('article',`portal-card ticket-message ${item.team?'from-team':'from-user'}`);
    const author=el('strong');if(item.team)author.append(el('span','team-message-tag','TEAM'),document.createTextNode(' '));author.append(document.createTextNode(item.authorName||'Nutzer'));
    article.append(author,el('span','portal-meta',` · ${meta(item.createdAt)}`),el('p','portal-message',item.body||''));
    if(item.attachments?.length)article.append(attachmentNodes(ticketId,item.attachments));
    return article;
  }
  async function load() {
    const url=`/api/index.php?route=team_data&view=${encodeURIComponent(view)}${view==='ticket'?'&id='+encodeURIComponent(ticketId):''}`;
    const response=await fetch(url,{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
    const data=await response.json();
    if(!response.ok) {const error=new Error(data.error||'Die Seite konnte nicht geladen werden.');error.status=response.status;throw error;}
    state=data;
    const statusMessage=query.get('message');
    if(view==='team_login')renderLogin(data);
    else if(view==='support')renderSupport(data);
    else if(view==='team')renderTeam(data);
    else if(view==='ticket')renderTicket(data);
    if(statusMessage)displayMessage(statusMessage);
  }
  function renderLogin(data) {
    if(data.signed_in){location.replace('/team.html');return;}
    root.replaceChildren(el('h1','portal-title','Teamanmeldung.'),el('p','portal-subtitle','Melde dich mit deinem Iron Shield Teamkonto an.'));
    const f=form('portal-card','team_login');hidden(f,'csrf',data.csrf);
    const username=input('username','','text',32);username.autocomplete='username';
    const password=input('password','','password',200);password.autocomplete='current-password';
    f.append(label('Benutzername',username),label('Passwort',password));
    const actions=el('div','portal-actions');actions.append(button('Anmelden'),anchor('/','portal-button secondary','Zur Startseite'));f.append(actions);root.append(f);
  }
  function renderSupport(data) {
    const staff=Boolean(data.staff);
    root.replaceChildren(el('span','portal-kicker','OFFIZIELLE SUPPORT-SEITE · IRON SHIELD'),el('h1','portal-title',staff?'Support-Postfach.':'Deine Support-Tickets.'),el('p','portal-subtitle',staff?'Hier siehst und bearbeitest du die Tickets der Community.':'Öffne ein Ticket und kommuniziere direkt mit unserem Team.'));
    if(!staff&&!data.discord_user){root.append(el('section','portal-feature', 'Melde dich mit Discord an, um ein Ticket zu öffnen und mit unserem Team zu kommunizieren.'));root.lastChild.append(anchor('/api/index.php?route=login','portal-button','Mit Discord anmelden und Ticket öffnen ↗'));return;}
    if(!staff) {
      const f=form('portal-card ticket-form','ticket_create');f.enctype='multipart/form-data';hidden(f,'csrf',data.csrf);
      const heading=el('div','ticket-form-heading');const headingCopy=el('div');headingCopy.append(el('span','portal-kicker','NEUES ANLIEGEN'),el('h2','','Wie können wir helfen?'));heading.append(headingCopy,el('span','ticket-step','01 / 01'));
      f.append(heading,el('p','portal-muted','Beschreibe kurz, was passiert ist. Zusatzangaben helfen uns, schneller die passende Lösung zu finden.'));
      const subject=input('subject','Zum Beispiel: Frage zur Server-Sicherheit','text',120);f.append(label('Betreff',subject));
      const fields=el('div','portal-grid ticket-fields');
      const select=(name,values)=>{const s=el('select','portal-select');s.name=name;for(const [value,text] of values){const o=el('option','',text);o.value=value;s.append(o);}return s;};
      fields.append(label('Thema',select('category',Object.entries(categoryNames))),label('Dringlichkeit',select('priority',[['normal','Normal'],['high','Dringend']])));
      const serverSelect=select('server_id',[['','Kein bestimmter Server'],...data.guilds.map(g=>[g.id,g.name])]);fields.append(label('Betroffener Server',serverSelect,'optional'));f.append(fields);
      const body=textarea('body','Beschreibe das Problem oder deine Frage möglichst genau …',10000);f.append(label('Was ist passiert?',body));f.append(el('small','field-hint','Bitte sende keine Passwörter, Bot-Tokens oder vertraulichen Zugangsdaten.'));
      const file=el('input','portal-input media-upload');file.name='attachments[]';file.type='file';file.multiple=true;file.accept='image/jpeg,image/png,image/gif,image/webp,video/mp4,video/webm,video/quicktime';
      f.append(label('Bilder oder Videos anhängen',file,'optional · bis zu 3 Dateien, je max. 5 MB'));
      const extra=el('details','optional-details');extra.append(el('summary','','Zusätzliche Angaben · optional'));extra.append(label('Was hast du bereits ausprobiert?',textarea('tried','Schritte, Fehlermeldungen oder Zeitpunkt …',3000,true)));f.append(extra);
      const submitRow=el('div','ticket-submit-row');submitRow.append(button('Ticket öffnen ↗'),el('span','','Deine Antwort erscheint in deinem Support-Postfach.'));f.append(submitRow);
      f.addEventListener('submit',event=>{
        const files=[...file.files];
        if(files.length>3){event.preventDefault();displayMessage('Du kannst höchstens 3 Dateien anhängen.',true);return;}
        if(files.some(item=>item.size>5*1024*1024)){event.preventDefault();displayMessage('Eine Datei überschreitet die Grenze von 5 MB.',true);return;}
        if(String(data.max_attachment_bytes||0)!=='0'&&files.reduce((sum,item)=>sum+item.size,0)>Number(data.max_attachment_bytes)){event.preventDefault();displayMessage('Die Dateien überschreiten zusammen das Upload-Limit dieses Hostings. Bitte hänge weniger oder kleinere Dateien an.',true);}
      });
      root.append(f);
    }
    renderTicketList(data.tickets||[],staff);
  }
  function renderTicketList(tickets,staff) {
    if(!tickets.length){root.append(el('p','portal-muted','Noch keine Tickets vorhanden.'));return;}
    for(const ticket of tickets) {
      const a=anchor(`/ticket.html?id=${encodeURIComponent(ticket.id)}`,'portal-card portal-ticket');
      const title=el('div','ticket-list-title');title.append(el('strong','',ticket.subject),el('span',`ticket-state${ticket.status==='open'?' is-open':''}`,ticket.status==='open'?'Offen':'Geschlossen'));
      const info=[ticket.ownerName,meta(ticket.updatedAt),categoryNames[ticket.category]||categoryNames.question,ticket.serverName,ticket.priority==='high'?'Dringend':'',staff?`Zuständig: ${ticket.assignedName||'Nicht übernommen'}`:''].filter(Boolean).join(' · ');
      a.append(title,el('p','portal-meta',info));root.append(a);
    }
  }
  function renderTeam(data) {
    const navForm=document.querySelector('.portal-head form[action="/api/index.php?route=team_logout"]');if(navForm)navForm.querySelector('[name=csrf]').value=data.csrf;
    root.replaceChildren(el('h1','portal-title','Teamverwaltung.'),el('p','portal-subtitle',`Willkommen, ${data.staff.displayName||data.staff.username}${data.is_admin?' · Owner-Verwaltung':' · Teammitglied'}`));
    const actions=el('div','portal-actions');actions.append(anchor('/support.html','portal-button','Zum Support-Postfach'));root.append(actions);
    if(data.can_manage_users){
      const stats=el('section','portal-card');stats.append(el('span','portal-kicker','PERSISTENZ'),el('h2','','Datenspeicher'),el('p','portal-muted',`${data.stats.users} Teamkonten · ${data.stats.tickets} Tickets · ${data.stats.announcements} Ankündigungen`),el('p','portal-meta','Dauerhafte Speicherung ist aktiv.'));root.append(stats);
    }
    if(data.password_notice){const notice=el('section','portal-card password-notice');notice.append(el('strong','',`Neues Passwort für ${data.password_notice.displayName}`),el('p','','Dieses Passwort wird nur einmal angezeigt. Kopiere es und teile es sicher.'));const row=el('div','password-copy-row');const inputNode=input('temporary_password','','text');inputNode.readOnly=true;inputNode.value=data.password_notice.password;inputNode.id='new-team-password';const copy=el('button','portal-button secondary','Kopieren');copy.type='button';copy.addEventListener('click',()=>navigator.clipboard.writeText(inputNode.value).then(()=>copy.textContent='Kopiert'));row.append(inputNode,copy);notice.append(row,el('span','portal-meta',`Benutzername: ${data.password_notice.username}`));root.append(notice);}
    if(data.can_manage_users){
      const section=el('section','portal-card');section.append(el('span','portal-kicker','ZUGRIFF VERWALTEN'),el('h2','','Teamkonten'),el('p','portal-muted','Teammitglieder können Tickets lesen, übernehmen und beantworten.'));
      for(const user of data.users){const card=el('article','portal-card');card.append(el('strong','',`${user.displayName} (@${user.username})${user.admin?' · Admin':''}`));if(!user.admin){
        const rights=form('portal-actions','team_permissions');hidden(rights,'csrf',data.csrf);hidden(rights,'id',user.id);
        for(const [name,text] of [['users_manage','Teamkonten verwalten'],['announcements_manage','Ankündigungen verwalten']]){const l=el('label','portal-perms');const cb=el('input');cb.type='checkbox';cb.name='permissions[]';cb.value=name;cb.checked=Boolean(user.permissions?.[name]);l.append(cb,document.createTextNode(text));rights.append(l);}
        rights.append(button('Rechte speichern','portal-button secondary'));
        const reset=form('portal-actions','team_reset_password');hidden(reset,'csrf',data.csrf);hidden(reset,'id',user.id);reset.append(button('Passwort zurücksetzen','portal-button secondary'));
        card.append(rights,reset);
      }section.append(card);}
      const create=form('portal-card','team_create_user');hidden(create,'csrf',data.csrf);create.append(el('h3','','Teamkonto erstellen'));
      create.append(label('Anzeigename',input('display_name','Name','text',60)),label('Benutzername',input('username','Benutzername','text',32)),label('Passwort',input('password','Mindestens 12 Zeichen','password',200)));
      const options=el('div','portal-perms');for(const [name,text] of [['users_manage','Teamkonten verwalten'],['announcements_manage','Ankündigungen verwalten']]){const l=el('label','');const cb=el('input');cb.type='checkbox';cb.name='permissions[]';cb.value=name;l.append(cb,document.createTextNode(text));options.append(l);}create.append(options,button('Teamkonto anlegen'));section.append(create);root.append(section);
    }
    if(data.can_manage_announcements){
      const section=el('section','portal-card');section.append(el('span','portal-kicker','STARTSEITE'),el('h2','','Ankündigungen'));
      const create=form('portal-card','announcement_create');hidden(create,'csrf',data.csrf);create.append(label('Titel',input('title','Kurzer Titel','text',100)),label('Text',textarea('body','Mitteilung …',2000)));
      const expires=input('expires_at','','datetime-local');expires.required=false;create.append(label('Anzeigen bis',expires,'optional'),button('Ankündigung veröffentlichen'));section.append(create);
      for(const item of data.announcements){const card=el('article','portal-card');card.append(el('strong','',item.title),el('p','portal-message',item.body));const remove=form('portal-actions','announcement_delete');hidden(remove,'csrf',data.csrf);hidden(remove,'id',item.id);remove.append(button('Entfernen','portal-button secondary'));card.append(remove);section.append(card);}root.append(section);
    }
    renderTicketList(data.tickets||[],true);
  }
  function renderTicket(data) {
    const ticket=data.ticket;
    document.title=`Ticket ${ticket.id} · Iron Shield`;
    root.replaceChildren(el('span','portal-kicker',`IRON SHIELD SUPPORT-SEITE · TICKET ${ticket.id}`),el('h1','portal-title',ticket.subject),el('p','portal-subtitle',`${ticket.status==='open'?'Offen':'Geschlossen'} · erstellt von ${ticket.ownerName||'Discord-Nutzer'}${ticket.assignedName?' · zuständig: '+ticket.assignedName:' · noch nicht übernommen'}`));
    const actions=el('div','portal-actions');actions.append(anchor('/support.html','portal-button secondary','← Zurück zu Support'));
    if(data.can_claim){const claim=form('','ticket_claim');hidden(claim,'csrf',data.csrf);hidden(claim,'id',ticket.id);claim.append(button(ticket.assignedTo===data.staff.id?'Übernommen · erneut zuweisen':'Ticket übernehmen'));actions.append(claim);}
    root.append(actions);
    const context=el('section','portal-card ticket-context');context.append(el('span','portal-kicker','ANGABEN ZUM ANLIEGEN'));const grid=el('div','portal-grid');
    for(const [title,value] of [['Thema',categoryNames[ticket.category]||'Allgemeine Frage'],['Dringlichkeit',ticket.priority==='high'?'Dringend':'Normal'],['Server',ticket.serverName],['Server-ID',ticket.serverId],['Bereits ausprobiert',ticket.tried]])if(value){const cell=el('div');cell.append(el('span','portal-meta',title),title==='Bereits ausprobiert'?el('p','portal-message',value):el('strong','',value));grid.append(cell);}
    if(grid.childElementCount) {context.append(grid);root.append(context);}
    const messages=el('div');messages.id='ticket-live-messages';messages.dataset.ticketId=ticket.id;messages.dataset.messageCount=String(ticket.messages?.length||0);messageCount=Number(messages.dataset.messageCount);
    for(const item of ticket.messages||[])messages.append(messageNode(ticket.id,item));root.append(messages);
    if(ticket.status==='open'&&data.can_reply){const reply=form('portal-card ticket-reply-form','ticket_reply');reply.enctype='multipart/form-data';hidden(reply,'csrf',data.csrf);hidden(reply,'id',ticket.id);reply.append(label('Antwort',textarea('body','',10000)));const files=el('input','portal-input media-upload');files.type='file';files.name='attachments[]';files.multiple=true;files.accept='image/jpeg,image/png,image/gif,image/webp,video/mp4,video/webm,video/quicktime';reply.append(label('Bilder oder Videos anhängen',files,'optional · bis zu 3 Dateien, je max. 5 MB'),button('Antwort senden'));reply.addEventListener('submit',event=>{const selected=[...files.files];if(selected.length>3||selected.some(file=>file.size>5*1024*1024)){event.preventDefault();displayMessage('Bitte höchstens 3 Dateien mit je maximal 5 MB anhängen.',true);}else if(selected.reduce((sum,file)=>sum+file.size,0)>Number(data.max_attachment_bytes||15*1024*1024)){event.preventDefault();displayMessage('Die Dateien überschreiten zusammen das Upload-Limit dieses Hostings.',true);}});root.append(reply);}
    if(data.can_close){const close=form('ticket-close-form','ticket_close');hidden(close,'csrf',data.csrf);hidden(close,'id',ticket.id);const closeButton=button('Ticket schließen','portal-button secondary');closeButton.addEventListener('click',event=>{if(!confirm('Ticket wirklich schließen? Danach kannst du nicht mehr antworten.'))event.preventDefault();});close.append(closeButton);root.append(close);}
    if(ticket.status==='open')setInterval(()=>pollMessages(ticket.id,messages),2500);
  }
  async function pollMessages(id,box) {
    if(polling||document.hidden)return;polling=true;
    try {
      const response=await fetch(`/api/index.php?route=ticket_poll&id=${encodeURIComponent(id)}&after=${messageCount}`,{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
      if(!response.ok)return;const data=await response.json();if(data.status!=='open'){location.reload();return;}
      for(const item of data.messages||[]){box.append(messageNode(id,item));messageCount++;box.dataset.messageCount=String(messageCount);}
    } catch {} finally {polling=false;}
  }
  load().catch(error=>{
    root.replaceChildren();
    if(error.status===401&&view==='support') {root.append(el('span','portal-kicker','OFFIZIELLE SUPPORT-SEITE · IRON SHIELD'),el('h1','portal-title','Iron Shield Support.'),el('p','portal-subtitle','Melde dich mit Discord an, um ein Ticket zu öffnen und direkt mit dem Team zu kommunizieren.'),anchor('/api/index.php?route=login','portal-button','Mit Discord anmelden und Ticket öffnen ↗'));}
    else if(error.status===401&&view==='team') {location.replace('/team-login.html');}
    else {root.append(el('p','portal-flash is-error',error.message||'Die Seite konnte nicht geladen werden.'));}
  });
})();
