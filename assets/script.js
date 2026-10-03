const menuButton = document.querySelector('.menu-toggle');
const navigation = document.querySelector('.main-nav');

const translations = {
  de: {
    navFeatures: 'Funktionen', navSteps: 'So funktioniert’s', navFaq: 'FAQ',
    heroEyebrow: '<span class="status-dot"></span> DEIN SERVER. DEIN SCHUTZ.', heroTitle: 'Dein Discord.<br><span>Unter Kontrolle.</span>',
    heroLead: 'Iron Shield hält deinen Server sicher — mit zuverlässiger Moderation, cleveren Schutzfunktionen und Logs, die wirklich Überblick schaffen.',
    discover: '<span class="play-icon">↓</span> Funktionen entdecken', proof: 'Mehr Sicherheit. Weniger Stress.', preview: 'Iron Shield Sicherheitsfunktionen',
    status: 'SERVER-STATUS', safe: 'Alles im grünen Bereich', protection: 'SCHUTZ AKTIV', detected: 'Verdächtiges erkannt', blocked: 'BLOCKIERT', caption: 'WACHSAM. ZUVERLÄSSIG. BEREIT.',
    heroBottom1: 'GEMACHT FÜR DEINE COMMUNITY', heroBottom2: '01 — SICHERHEIT, DIE MITDENKT', featureEyebrow: 'EIN SCHUTZSCHILD, VIELE MÖGLICHKEITEN',
    featureTitle: 'Weniger Chaos.<br><span>Mehr Community.</span>', featureLead: 'Die richtigen Werkzeuge, damit du dich auf das konzentrieren kannst, was deinen Server besonders macht.',
    featureIndex1: '01 / SCHUTZ', featureTitle1: 'Bedrohungen früh erkennen', featureText1: 'Iron Shield behält auffällige Aktivitäten im Blick und hilft dir, auf verdächtige Aktionen schnell zu reagieren.',
    featureIndex2: '02 / MODERATION', featureTitle2: 'Moderation mit Überblick', featureText2: 'Behalte Vorgänge im Auge und schaffe klare Abläufe für dein Team.',
    featureIndex3: '03 / TRANSPARENZ', featureTitle3: 'Alles sauber dokumentiert', featureText3: 'Logs geben deinem Team nachvollziehbare Einblicke in wichtige Ereignisse.', more: 'Mehr erfahren',
    stepsEyebrow: 'IN WENIGEN SCHRITTEN BEREIT', stepsTitle: 'Einrichten.<br><span>Durchatmen.</span>',
    stepsLead: 'Der Start ist unkompliziert. Du behältst die Kontrolle darüber, welche Berechtigungen Iron Shield auf deinem Server erhält.', getStarted: 'Jetzt loslegen',
    stepTitle1: 'Bot hinzufügen', stepText1: 'Lade Iron Shield über den Einladungsbutton auf deinen Discord-Server ein.',
    stepTitle2: 'Berechtigungen prüfen', stepText2: 'Wähle die passenden Berechtigungen aus und bestätige die Einladung bei Discord.',
    stepTitle3: 'Schutz konfigurieren', stepText3: 'Richte Iron Shield passend zu den Regeln und Abläufen deiner Community ein.',
    faqEyebrow: 'GUT ZU WISSEN', faqTitle: 'Häufige Fragen<span>.</span>', faqLead: 'Du möchtest vor dem Start noch etwas wissen? Hier findest du Antworten.',
    faqQ1: 'Was ist Iron Shield?', faqA1: 'Iron Shield ist ein Sicherheits- und Moderationsbot für Discord. Er unterstützt Serverteams dabei, Aktivitäten im Blick zu behalten und ihre Community zu schützen.',
    faqQ2: 'Wie lade ich den Bot ein?', faqA2: 'Klicke auf „Iron Shield einladen“ und folge dem Discord-Autorisierungsdialog. Prüfe die angefragten Berechtigungen, bevor du die Einladung bestätigst.',
    faqQ3: 'Welche Berechtigungen braucht der Bot?', faqA3: 'Das hängt davon ab, welche Funktionen du verwenden möchtest. Vergib nur die Berechtigungen, die für deine gewünschte Einrichtung erforderlich sind.',
    faqQ4: 'Wo bekomme ich Hilfe?', faqA4: 'Nutze den Support-Button, um den offiziellen Support-Bereich zu öffnen. Dort kann dir das Iron Shield Team weiterhelfen.',
    inviteEyebrow: '<span class="status-dot"></span> BEREIT, DEINEN SERVER ZU SCHÜTZEN?', inviteTitle: 'Mach deinen Server<br>zum <span>sicheren Ort.</span>', inviteLead: 'Hol Iron Shield in deine Community und behalte die Kontrolle über das, was zählt.', inviteBot: 'Bot zu Discord hinzufügen', support: 'Support kontaktieren',
    footerNote: 'Mit Bedacht entwickelt. Für starke Communities.', privacy: 'Datenschutz', terms: 'Nutzungsbedingungen', legal: 'Impressum', backTop: 'ZURÜCK NACH OBEN <span>↑</span>',
  },
  en: {
    navFeatures: 'Features', navSteps: 'How it works', navFaq: 'FAQ',
    heroEyebrow: '<span class="status-dot"></span> YOUR SERVER. YOUR SHIELD.', heroTitle: 'Your Discord.<br><span>Under control.</span>',
    heroLead: 'Iron Shield helps keep your server safe with reliable moderation, smart protection tools, and clear activity logs.',
    discover: '<span class="play-icon">↓</span> Explore features', proof: 'More security. Less stress.', preview: 'Iron Shield security features',
    status: 'SERVER STATUS', safe: 'Everything looks good', protection: 'PROTECTION ACTIVE', detected: 'Suspicious activity found', blocked: 'BLOCKED', caption: 'ALERT. RELIABLE. READY.',
    heroBottom1: 'BUILT FOR YOUR COMMUNITY', heroBottom2: '01 — SECURITY THAT THINKS AHEAD', featureEyebrow: 'ONE SHIELD. MANY POSSIBILITIES.',
    featureTitle: 'Less chaos.<br><span>More community.</span>', featureLead: 'The right tools help you focus on what makes your server special.',
    featureIndex1: '01 / PROTECTION', featureTitle1: 'Spot threats early', featureText1: 'Iron Shield watches for unusual activity and helps you respond quickly to suspicious actions.',
    featureIndex2: '02 / MODERATION', featureTitle2: 'Moderation with clarity', featureText2: 'Keep track of incidents and give your team clear workflows.',
    featureIndex3: '03 / TRANSPARENCY', featureTitle3: 'Clear activity records', featureText3: 'Logs give your team a useful, traceable view of important events.', more: 'Learn more',
    stepsEyebrow: 'READY IN A FEW STEPS', stepsTitle: 'Set it up.<br><span>Take a breath.</span>',
    stepsLead: 'Getting started is simple. You stay in control of the permissions Iron Shield receives on your server.', getStarted: 'Get started',
    stepTitle1: 'Add the bot', stepText1: 'Invite Iron Shield to your Discord server using the invite button.',
    stepTitle2: 'Review permissions', stepText2: 'Choose the permissions you need and confirm the invite with Discord.',
    stepTitle3: 'Configure protection', stepText3: 'Set up Iron Shield to fit your community rules and workflows.',
    faqEyebrow: 'GOOD TO KNOW', faqTitle: 'Frequently asked questions<span>.</span>', faqLead: 'Have questions before getting started? Find answers here.',
    faqQ1: 'What is Iron Shield?', faqA1: 'Iron Shield is a security and moderation bot for Discord. It helps server teams monitor activity and protect their community.',
    faqQ2: 'How do I invite the bot?', faqA2: 'Click “Add Iron Shield” and follow Discord’s authorization flow. Review the requested permissions before confirming.',
    faqQ3: 'What permissions does the bot need?', faqA3: 'It depends on the features you want to use. Grant only the permissions needed for your setup.',
    faqQ4: 'Where can I get help?', faqA4: 'Use the support button to open the official support area, where the Iron Shield team can help you.',
    inviteEyebrow: '<span class="status-dot"></span> READY TO PROTECT YOUR SERVER?', inviteTitle: 'Make your server<br>a <span>safer place.</span>', inviteLead: 'Bring Iron Shield to your community and stay in control of what matters.', inviteBot: 'Add bot to Discord', support: 'Contact support',
    footerNote: 'Made with care. For strong communities.', privacy: 'Privacy', terms: 'Terms', legal: 'Legal notice', backTop: 'BACK TO TOP <span>↑</span>',
  }
};

let preferences = { accent: 'green', theme: 'dark', language: 'de' };

function t(key) { return translations[preferences.language][key] || translations.de[key] || key; }
function put(selector, key, html = false) {
  const node = document.querySelector(selector);
  if (node) html ? node.innerHTML = t(key) : node.textContent = t(key);
}
function translatePage() {
  document.documentElement.lang = preferences.language;
  const map = [
    ['.main-nav a[href="#funktionen"]', 'navFeatures'], ['.main-nav a[href="#so-gehts"]', 'navSteps'], ['.main-nav a[href="#faq"]', 'navFaq'],
    ['.hero-copy .eyebrow', 'heroEyebrow', true], ['.hero h1', 'heroTitle', true], ['.hero-lede', 'heroLead'], ['.hero-actions .button-quiet', 'discover', true], ['.hero-proof>span', 'proof'],
    ['.card-secure small', 'status'], ['.card-secure strong', 'safe'], ['.card-alert small', 'protection'], ['.card-alert strong', 'detected'], ['.alert-tag', 'blocked'], ['.visual-caption span:last-child', 'caption'],
    ['.hero-bottom span:first-child', 'heroBottom1'], ['.hero-bottom span:last-child', 'heroBottom2'], ['.section-heading .eyebrow', 'featureEyebrow'], ['.section-heading h2', 'featureTitle', true], ['.section-heading>p', 'featureLead'],
    ['.feature-card:nth-child(1) .feature-index', 'featureIndex1'], ['.feature-card:nth-child(1) h3', 'featureTitle1'], ['.feature-card:nth-child(1) p', 'featureText1'],
    ['.feature-card:nth-child(2) .feature-index', 'featureIndex2'], ['.feature-card:nth-child(2) h3', 'featureTitle2'], ['.feature-card:nth-child(2) p', 'featureText2'],
    ['.feature-card:nth-child(3) .feature-index', 'featureIndex3'], ['.feature-card:nth-child(3) h3', 'featureTitle3'], ['.feature-card:nth-child(3) p', 'featureText3'],
    ['.steps-copy .eyebrow', 'stepsEyebrow'], ['.steps-copy h2', 'stepsTitle', true], ['.steps-copy>p', 'stepsLead'], ['.steps-copy .button-outline', 'getStarted'],
    ['.step-item:nth-child(1) h3', 'stepTitle1'], ['.step-item:nth-child(1) p', 'stepText1'], ['.step-item:nth-child(2) h3', 'stepTitle2'], ['.step-item:nth-child(2) p', 'stepText2'], ['.step-item:nth-child(3) h3', 'stepTitle3'], ['.step-item:nth-child(3) p', 'stepText3'],
    ['.faq-heading .eyebrow', 'faqEyebrow'], ['.faq-heading h2', 'faqTitle', true], ['.faq-heading>p', 'faqLead'],
    ['.invite-content .eyebrow', 'inviteEyebrow', true], ['.invite-content h2', 'inviteTitle', true], ['.invite-content>p', 'inviteLead'], ['.invite-actions .button-primary', 'inviteBot'], ['.invite-actions .button-quiet', 'support'], ['.footer-note', 'footerNote'],
    ['.footer-legal a:nth-child(1)', 'privacy'], ['.footer-legal a:nth-child(2)', 'terms'], ['.footer-legal a:nth-child(3)', 'legal'], ['.back-top', 'backTop', true]
  ];
  map.forEach(([selector, key, html]) => put(selector, key, html));
  document.querySelector('.hero-visual')?.setAttribute('aria-label', t('preview'));
  document.querySelectorAll('.feature-card .text-link').forEach((link) => { link.innerHTML = `${t('more')} <span>↗</span>`; });
  document.querySelectorAll('.faq-item').forEach((item, index) => {
    const summary = item.querySelector('summary');
    if (summary?.firstChild) summary.firstChild.textContent = t(`faqQ${index + 1}`);
    const answer = item.querySelector('p');
    if (answer) answer.textContent = t(`faqA${index + 1}`);
  });
}

function savePreferences() {
  document.body.dataset.accent = preferences.accent;
  document.body.dataset.theme = preferences.theme;
  translatePage();
}
savePreferences();

menuButton?.addEventListener('click', () => {
  const isOpen = menuButton.getAttribute('aria-expanded') === 'true';
  menuButton.setAttribute('aria-expanded', String(!isOpen));
  menuButton.setAttribute('aria-label', isOpen ? (preferences.language === 'en' ? 'Open menu' : 'Menü öffnen') : (preferences.language === 'en' ? 'Close menu' : 'Menü schließen'));
  navigation?.classList.toggle('open', !isOpen);
});
navigation?.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => {
  navigation.classList.remove('open'); menuButton?.setAttribute('aria-expanded', 'false');
}));


