<?php
declare(strict_types=1);

function legal_escape(string $text): string
{
    $html = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $html = preg_replace('/\*\*(.+?)\*\*/u', '<strong>$1</strong>', $html) ?? $html;
    $html = preg_replace_callback('/https:\/\/[^\s<]+/u', static function ($match) {
        $url = rtrim($match[0], '.,;:)');
        $tail = substr($match[0], strlen($url));
        $safe = htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
        return '<a href="' . $safe . '" target="_blank" rel="noopener noreferrer">' . $safe . '</a>' . $tail;
    }, $html) ?? $html;
    $html = preg_replace('/(?<![\w"\/])([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})/u', '<a href="mailto:$1">$1</a>', $html) ?? $html;
    return $html;
}

function legal_render(string $document): array
{
    $html = '';
    $toc = [];
    $listOpen = false;
    $plainList = false;
    $sectionNumber = 0;
    foreach (preg_split('/\r\n|\r|\n/', trim($document)) ?: [] as $line) {
        $line = trim($line);
        if ($line === '') {
            if ($listOpen) { $html .= '</ul>'; $listOpen = false; }
            $plainList = false;
            continue;
        }
        if ($line === 'Datenschutzerklärung' || str_starts_with($line, 'Zuletzt aktualisiert:')) continue;
        $level = 0;
        $heading = '';
        if (preg_match('/^(#{2,3})\s+(.+)$/u', $line, $matches)) {
            $level = strlen($matches[1]);
            $heading = $matches[2];
        } elseif (preg_match('/^(\d+\.\s+.+)$/u', $line, $matches)) {
            $level = 2;
            $heading = $matches[1];
        } elseif (preg_match('/^([a-d]\)\s+.+)$/iu', $line, $matches)) {
            $level = 3;
            $heading = $matches[1];
        }
        if ($level) {
            if ($listOpen) { $html .= '</ul>'; $listOpen = false; }
            $plainList = false;
            $safeHeading = legal_escape($heading);
            if ($level === 2) {
                if ($sectionNumber > 0) $html .= '</section>';
                $sectionNumber++;
                $id = 'abschnitt-' . $sectionNumber;
                $toc[] = ['id' => $id, 'title' => $heading];
                $html .= '<section class="legal-section"><h2 id="' . $id . '">' . $safeHeading . '</h2>';
            } else {
                $html .= '<h3>' . $safeHeading . '</h3>';
            }
            continue;
        }
        if (str_starts_with($line, '- ')) {
            if (!$listOpen) { $html .= '<ul>'; $listOpen = true; }
            $html .= '<li>' . legal_escape(substr($line, 2)) . '</li>';
            $plainList = false;
            continue;
        }
        if ($plainList && !preg_match('/^(?:[a-d]\)|\d+\.)/u', $line)) {
            if (!$listOpen) { $html .= '<ul>'; $listOpen = true; }
            $html .= '<li>' . legal_escape($line) . '</li>';
            continue;
        }
        if ($listOpen) { $html .= '</ul>'; $listOpen = false; }
        $html .= '<p>' . legal_escape($line) . '</p>';
        $plainList = str_ends_with($line, ':');
    }
    if ($listOpen) $html .= '</ul>';
    if ($sectionNumber > 0) $html .= '</section>';
    return [$html, $toc];
}

$documents = [
    'datenschutz' => [
        'title' => 'Datenschutzerklärung',
        'updated' => '1. Oktober 2026',
        'text' => <<<'PRIVACY'
Datenschutzerklärung
Zuletzt aktualisiert: September 2026

1. Verantwortliche nach Art. 26 DSGVO (Gemeinsame Verantwortlichkeit)
Gemeinsam Verantwortliche im Sinne der Datenschutz-Grundverordnung (DSGVO) für die Verarbeitung personenbezogener Daten im Zusammenhang mit IronShield sind:

Sebastian Stephan
Ollersdorferstraße 13
2261 Angern an der March
Österreich
E-Mail: ironshield.sebi@outlook.com
Telefon: +43 677 64305512

Levi Markewski
Heußstraße 38
70794 Filderstadt
Deutschland
E-Mail: ironshield.levi@outlook.de
Telefon: +49 152 33549222

Sebastian Stephan und Levi Markewski sind gemeinsam Verantwortliche im Sinne von Art. 26 DSGVO für Zwecke und Mittel der Datenverarbeitung im Rahmen von IronShield.

Interne Aufgabenverteilung
Sebastian Stephan ist insbesondere verantwortlich für die Organisation des Datenschutzes, die Bearbeitung von Betroffenenanfragen sowie die Verwaltung und Kontrolle personenbezogener Daten im Zusammenhang mit IronShield.
Levi Markewski ist insbesondere verantwortlich für die technische Entwicklung, Wartung und Weiterentwicklung des Systems sowie die Implementierung neuer Funktionen.
Betroffene Personen können sich zur Ausübung ihrer Rechte jederzeit an beide Verantwortliche wenden.

2. Allgemeine Informationen
IronShield ist ein Discord-Bot zur Moderation, Sicherheit, Verwaltung und Automatisierung von Discord-Servern. Der Bot verarbeitet personenbezogene Daten ausschließlich zur Bereitstellung seiner Funktionen auf Grundlage von Nutzeraktionen innerhalb von Discord sowie zur technischen Ausführung der angeforderten Funktionen und zum sicheren Betrieb des Dienstes.

3. Datenverarbeitung durch Discord
IronShield wird auf der Plattform Discord betrieben. Bei der Nutzung von Discord werden personenbezogene Daten durch Discord verarbeitet. Dabei kann es zu einer Übermittlung in Drittländer, insbesondere in die USA, kommen. Die Übermittlung erfolgt auf Grundlage geeigneter Garantien gemäß Art. 46 DSGVO (Standardvertragsklauseln). Für die Verarbeitung durch Discord gelten die Datenschutzbestimmungen von Discord.

4. Verarbeitete Daten
Je nach Nutzung verarbeitet IronShield insbesondere:

Discord User-ID
Server-ID
Channel-ID
Rollen-IDs
Nachrichteninhalte (nur soweit funktional erforderlich)
Interaktionsdaten (Commands, Buttons, Menüs)
technische Logdaten
Server-Logdaten (z. B. IP-Adresse, Zeitpunkt, Fehlerprotokolle, Systemereignisse)
Zusätzlich im Rahmen von Moderation:

Verwarnungen (Warnings), Mutes, Kicks, Bans, Entbannungen & sonstige Moderationsmaßnahmen
Zeitpunkt der Erstellung eines Discord-Kontos und des Beitritts zum Server, öffentliches Profilbild und öffentlicher Anzeigename — für Sicherheitsprüfungen (siehe Abschnitt 15)
bei Team-Abstimmungen: abgegebene Stimmen, die begründende Freitextangabe und die beteiligten Personen (siehe Abschnitt 15)
Datenbankspeicherung: Serverkonfigurationen, Bot-Einstellungen, Moderationsdaten, Sicherheitskonfigurationen sowie Rollen- und Kanalzuweisungen. Die Speicherung erfolgt nur solange, wie sie für die Funktionsfähigkeit von IronShield erforderlich ist.

5. Rechtsgrundlagen der Verarbeitung
Die Verarbeitung personenbezogener Daten erfolgt auf Grundlage von Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse). Unser berechtigtes Interesse liegt im Betrieb, der Sicherheit, Stabilität, dem Missbrauchsschutz sowie der Bereitstellung und Funktionsfähigkeit des Discord-Bots im Rahmen der durch die Nutzer ausgelösten Aktionen.

6. Zweck der Verarbeitung
Betrieb des Discord-Bots & Bereitstellung der Funktionen
Moderation und Verwaltung von Servern
Sicherheits- und Missbrauchsschutz (Spam- und Raid-Erkennung)
Erkennung von Umgehungen einer Sperre und von Mehrfachkonten (siehe Abschnitt 15)
Durchführung von Team-Abstimmungen auf Wunsch der Serverleitung
Fehleranalyse und Stabilität
7. Speicherdauer
Daten werden nur so lange gespeichert, wie dies für die Funktionsfähigkeit von IronShield erforderlich ist. Während der aktiven Nutzung können Daten gespeichert bleiben. Nach der Entfernung des Bots von einem Server werden alle zugehörigen Daten innerhalb von 14 Tagen gelöscht, sofern keine gesetzlichen Pflichten bestehen.

Für einzelne Funktionen gelten darüber hinaus feste Fristen:

Team-Abstimmungen: Eine abgeschlossene Abstimmung wird 30 Tage nach ihrem Ende automatisch gelöscht. Die Sperrfrist, die eine erneute Abstimmung über dieselbe Person verhindert, wird mit ihrem Ablauf gelöscht (Voreinstellung: 7 Tage).
Zweitkonten-Prüfung: Es werden keine personenbezogenen Ergebnisse gespeichert. Die Auswertung entsteht bei jedem Aufruf neu und besteht nur als Meldung im gewählten Discord-Kanal fort; deren Aufbewahrung richtet sich nach den Einstellungen des jeweiligen Servers. Die Bannliste eines Servers wird für höchstens 10 Minuten im Arbeitsspeicher zwischengespeichert.
Account-Alter-Prüfung: Es wird nur die Server-Einstellung gespeichert, kein Ergebnis zu einzelnen Personen.
8. Hosting und technische Infrastruktur
Die Support-Webseite unter https://ironshield.novium.link/ wird auf einem von Novium bereitgestellten Webspace betrieben. Die öffentlich zugänglichen Anbieterangaben nennen Niclas Müller, c/o IP-Management #9613, Ludwig-Erhard-Straße 18, 20459 Hamburg, sowie support@novium.world; siehe https://novium.world/legal/impressum.

Beim Aufruf des Dashboards kann der Hosting-Anbieter technisch erforderliche Verbindungs- und Serverdaten verarbeiten, insbesondere IP-Adresse, Datum und Uhrzeit, angeforderte URL, Browser- und Geräteinformationen sowie Fehler- und Sicherheitsprotokolle. Diese Verarbeitung dient der Bereitstellung, Stabilität und Absicherung der Website. Rechtsgrundlage ist Art. 6 Abs. 1 lit. f DSGVO.

Die öffentlich verfügbaren Anbieterangaben belegen nicht den konkreten Speicherort dieses Webspace, die Aufbewahrungsdauer der Serverprotokolle oder mögliche Drittlandübermittlungen. Diese Einzelheiten richten sich nach den für das Projekt geltenden Hosting-Vereinbarungen und den Datenschutzinformationen des Anbieters. Deshalb geben wir hierzu keine Zusicherung eines bestimmten Serverstandorts oder eines Ausschlusses von Drittlandübermittlungen ab. Die technische Infrastruktur des Discord-Bots kann hiervon getrennt betrieben werden.

9. Rechte der Nutzer
Du hast folgende Rechte bezüglich deiner Daten nach der DSGVO:

Recht auf Auskunft (Art. 15)
Recht auf Berichtigung (Art. 16)
Recht auf Löschung (Art. 17)
Recht auf Einschränkung (Art. 18)
Recht auf Datenübertragbarkeit (Art. 20)
Recht auf Widerspruch (Art. 21)
Beschwerderecht bei einer zuständigen Aufsichtsbehörde
10. Datensicherheit
Wir setzen technische Schutzmaßnahmen ein, darunter Zugriffskontrollen, Authentifizierungssysteme, Schutz vor unbefugtem Missbrauch sowie die Protokollierung sicherheitsrelevanter Ereignisse.

11. Verarbeitung durch Claude KI
IronShield kann zur Unterstützung einzelner Funktionen die KI Claude einsetzen. Dabei werden ausschließlich die für die jeweilige Anfrage erforderlichen Inhalte an Claude übermittelt. Claude speichert die übermittelten Inhalte nicht dauerhaft und verwendet sie nicht zum Training oder zur Verbesserung eigener KI-Modelle. Eine dauerhafte Speicherung personenbezogener Daten durch Claude erfolgt im Rahmen der Nutzung von IronShield nicht.

12. Änderungen
Diese Datenschutzerklärung kann jederzeit angepasst werden.

13. Kontakt
Sebastian Stephan: ironshield.sebi@outlook.com
Levi Markewski: ironshield.levi@outlook.de

14. Support-Webseite unter ironshield.novium.link
Anmeldung: Für den Discord-Login verwendet die Website OAuth2 mit den Scopes identify und guilds. Discord-Benutzer-ID, Benutzername und Profilbild dienen der Anmeldung und Zuordnung eigener Support-Tickets. Die Serverliste des angemeldeten Kontos wird abgefragt, damit beim Erstellen eines Tickets optional ein betroffener Server ausgewählt werden kann. In der Sitzung werden dafür nur die Server-IDs und Namen vorgehalten; Rollen, Kanäle und Bot-Installationsstatus werden nicht abgefragt. Der OAuth-Zugriffstoken wird nur beim Rückruf von Discord serverseitig verwendet und danach nicht in der Sitzung gespeichert.

Sitzung und Sicherheit: Die PHP-Sitzung nutzt ein HttpOnly-Cookie namens is_sess; für die HTTPS-Website wird es mit dem Secure-Attribut und SameSite=Lax gesetzt. Die Sitzung enthält eine zufällige Sitzungskennung und die für Support-Tickets benötigten Discord-Profilangaben. Sie endet nach acht Stunden Inaktivität und wird beim Abmelden gelöscht. Zum Schutz des OAuth-Rücksprungs setzt die Website für jeden Loginversuch ein eigenes kurzlebiges HttpOnly- und SameSite=Lax-Cookie mit dem Statuswert. Es wird nach höchstens zehn Minuten ungültig; für HTTPS wird auch dieses Cookie mit Secure gesetzt. Der Statuswert wird ergänzend in der PHP-Sitzung für denselben Zeitraum vorgehalten, damit der Rücksprung geprüft werden kann.

Schriftarten: Die Website verwendet die im jeweiligen Betriebssystem vorhandenen Schriftarten. Dafür wird kein externer Schriftanbieter aufgerufen.

Ankündigungen, Teamkonten und Tickets: Teammitglieder mit entsprechender Berechtigung können Titel, Nachricht, Veröffentlichungszeit und optionalen Ablaufzeitpunkt einer öffentlichen Ankündigung speichern. Aktive Ankündigungen werden auf der Startseite angezeigt und nach Ablauf automatisch ausgeblendet.

Speicherung, Teamkonten und Tickets: Die Support-Webseite verwendet keine SQL-Datenbank und keine Werbe- oder Reichweitenanalyse. Für Teamkonten und Support-Tickets speichert sie serverseitig eine private Datei. Bei Teamkonten werden Anzeigename, Benutzername, Passwort-Hash, zugewiesene Verwaltungsrechte und Erstellungszeit verarbeitet; Passwörter werden nicht im Klartext gespeichert. Ein von der Administration zurückgesetztes Passwort wird einmalig in der Team-Sitzung zur Weitergabe angezeigt und nicht dauerhaft im Klartext gespeichert. Bei Tickets werden Discord-ID und Discord-Name der anfragenden Person, Betreff, Nachrichten, Thema, Dringlichkeit, der optional ausgewählte Servername und die Server-ID, Status, zuständiges Teammitglied sowie Zeitangaben gespeichert. Beim Erstellen eines Tickets übermittelt die Website Ticket-ID, Discord-Anzeigename, Betreff, Thema, Dringlichkeit, ausgewählten Server (falls vorhanden) und den Nachrichtentext an den in der Konfiguration festgelegten Discord-Support-Kanal. Dort erstellt der Iron Shield Bot einen Ticket-Thread und veröffentlicht diese Angaben, damit das Team über Discord benachrichtigt wird. Nutzer können ihren Ticketverlauf mit Bildern oder Videos ergänzen und ihre eigenen Tickets schließen. Hochgeladene Dateien werden im privaten Teamdatenspeicher aufbewahrt und nur für die anfragende Person und angemeldete Teammitglieder ausgeliefert. Inhalte bleiben zur Bearbeitung und Nachvollziehbarkeit des Supports gespeichert, bis sie gelöscht werden. Ticketinhalte sind für die anfragende Person sowie angemeldete Teammitglieder sichtbar; Teammitglieder können Tickets übernehmen und beantworten. Die Daten liegen standardmäßig in einem privaten, gegen direkte Webzugriffe gesperrten Ordner auf dem Server. Bei Nutzung eines Hosting-Volumes hängt die Aufbewahrung zusätzlich von dessen Konfiguration ab.

Speicher im Browser: Die Website liest oder speichert keine Einstellungen im localStorage. Das notwendige Sitzungscookie is_sess und die kurzlebigen OAuth-Statuscookies dienen ausschließlich Anmeldung und Sitzungsverwaltung; ein Cookie-Banner oder Tracking-Cookies sind derzeit nicht eingebunden.

15. Sicherheitsprüfungen und Team-Abstimmungen
Einige Funktionen von IronShield werten Angaben zu einzelnen Personen aus. Weil das über die reine Bereitstellung hinausgeht, erläutern wir sie hier gesondert.

a) Prüfung des Konto-Alters
Tritt jemand einem Server bei, kann IronShield prüfen, wie lange das Discord-Konto bereits besteht. Der Zeitpunkt der Konto-Erstellung ist Bestandteil jeder Discord-ID und damit öffentlich. Liegt das Alter unter der vom Server festgelegten Grenze, wird eine Meldung in einen vom Server bestimmten Kanal geschrieben. Serverbetreiber können zusätzlich eine automatische Entfernung vom Server (Kick) aktivieren; diese Einstellung ist standardmäßig aus. Ein Kick beendet lediglich die Mitgliedschaft auf dem betreffenden Discord-Server und lässt das Discord-Konto unberührt; ein erneuter Beitritt bleibt möglich. Auf Anforderung der Serverleitung können auch bereits vorhandene Mitglieder angezeigt werden, deren Konto jünger als eine wählbare Grenze ist. Diese Anzeige wird bei jedem Aufruf neu erzeugt und nicht gespeichert.

b) Prüfung auf Mehrfach- und Umgehungskonten
Diese Funktion unterstützt Serverteams bei der Frage, ob ein Konto ein Zweitkonto sein könnte — insbesondere zur Umgehung einer bestehenden Sperre. Ausgewertet werden ausschließlich Angaben, die auf dem jeweiligen Server ohnehin sichtbar sind: Zeitpunkt der Konto-Erstellung und des Beitritts, das öffentliche Profilbild, der öffentliche Anzeige- und Benutzername sowie die Sperrliste des Servers. Daraus entsteht ein Hinweiswert mit ausgeschriebener Begründung.

Keine automatisierte Entscheidung im Einzelfall: Das Ergebnis ist ein Hinweis an das Serverteam. IronShield entfernt oder sperrt aufgrund dieser Auswertung niemanden selbsttätig; jede Maßnahme trifft ein Mensch, dem die Begründung vorliegt. Eine ausschließlich automatisierte Entscheidung im Sinne des Art. 22 DSGVO findet nicht statt.

Keine Speicherung von Ergebnissen: Hinweiswert und Begründung werden nicht in unserer Datenbank abgelegt. Sie entstehen bei jedem Aufruf neu. Gespeichert wird allein die Einstellung des Servers (aktiv, Schwellenwert, Meldekanal).

Serverübergreifender Abgleich: Optional kann berücksichtigt werden, auf wie vielen Servern, auf denen IronShield ebenfalls eingesetzt wird, zwei Konten gemeinsam vertreten sind. Diese Einstellung ist standardmäßig deaktiviert und muss vom jeweiligen Serverbetreiber bewusst eingeschaltet werden. Sie ist nur zulässig, soweit der Serverbetreiber hierüber selbst informiert; die Zahl wird ausschließlich als Mindestwert ausgewiesen und nicht gespeichert.

Aussagekraft: Discord stellt Bots keine IP-Adressen, Geräte- oder Bestandsdaten bereit. Die Auswertung kann daher nicht belegen, dass zwei Konten derselben Person gehören; sie liefert Anhaltspunkte, die derselben Person, aber ebenso Angehörigen im selben Haushalt oder Nutzern desselben Netzwerks entsprechen können. Betroffene können der Verarbeitung nach Art. 21 DSGVO widersprechen und eine Überprüfung des Ergebnisses verlangen (Abschnitt 9).

c) Team-Abstimmungen
Serverteams können darüber abstimmen, ob ein Teammitglied seine Team-Rollen behält. Verarbeitet werden dabei die Discord-IDs der betroffenen und der abstimmenden Personen, der angezeigte Name der betroffenen Person, die abgegebenen Stimmen sowie eine von der antragstellenden Person verfasste Begründung in Freitextform. Die Abstimmung findet offen statt: Der Verlauf einschließlich der Stimmen ist für die Teilnehmenden sichtbar, und die betroffene Person wird über die Abstimmung benachrichtigt.

Ein erfolgreicher Abschluss führt zum Entzug der Team-Rollen auf dem betreffenden Server. Eine Entfernung vom Server oder eine Sperre erfolgt dadurch nicht. Abgeschlossene Abstimmungen werden nach 30 Tagen gelöscht, die Sperrfrist mit ihrem Ablauf. Verlässt IronShield den Server, werden alle Abstimmungsdaten dieses Servers gelöscht.

Für die Freitext-Begründung ist die verfassende Person verantwortlich. Sie sollte sich auf sachliche, für die Entscheidung erforderliche Angaben beschränken; besondere Kategorien personenbezogener Daten nach Art. 9 DSGVO (etwa Angaben zu Gesundheit, Religion oder sexueller Orientierung) gehören nicht hinein.

d) Rechtsgrundlage und Widerspruch
Rechtsgrundlage ist Art. 6 Abs. 1 lit. f DSGVO. Das berechtigte Interesse besteht im Schutz der Server vor Sperrumgehung, Mehrfachkonten und automatisierten Konten sowie in der geordneten Verwaltung von Serverteams. Betroffene können der Verarbeitung jederzeit nach Art. 21 DSGVO widersprechen; die Kontaktwege stehen in Abschnitt 13. Serverbetreiber können die genannten Funktionen jederzeit vollständig abschalten.

16. Notfallzugriff auf Sicherheitssysteme
Bei einer akuten Gefahr für einen Server können die Betreiber von IronShield nach Abschnitt 5 der Nutzungsbedingungen mit Genehmigung des Server-Eigentümers auf die Sicherheitssysteme des Bots für diesen Server zugreifen. Dabei können die Betreiber personenbezogene Daten einsehen, die diese Systeme für den Server ohnehin verarbeiten: insbesondere Discord-IDs, Benutzer- und Anzeigenamen, Einträge in Sicherheits- und Moderationsprotokollen, Verwarnungen sowie Listen gesperrter oder in Quarantäne gesetzter Mitglieder.

Zweck ist ausschließlich die Abwehr der konkreten Gefahr für den Server und seine Mitglieder. Für den Notfallzugriff werden keine zusätzlichen Daten erhoben; es gelten die Speicherdauern der jeweiligen Systeme (Abschnitt 7). Zugreifen können nur die Betreiber von IronShield, also die Verantwortlichen aus Abschnitt 1 und die von ihnen als Bot-Administratoren eingesetzten Personen.

Rechtsgrundlage ist Art. 6 Abs. 1 lit. f DSGVO. Das berechtigte Interesse besteht im Schutz des Servers und seiner Mitglieder vor Angriffen wie Raids, Nukes oder kompromittierten Administrator-Konten; die Genehmigung des Server-Eigentümers begrenzt den Zugriff auf den Einzelfall. Betroffene können nach Art. 21 DSGVO widersprechen; die Kontaktwege stehen in Abschnitt 13.
PRIVACY,
    ],
    'nutzungsbedingungen' => [
        'title' => 'Nutzungsbedingungen',
        'updated' => '29. September 2026',
        'text' => <<<'TERMS'
## 1. Geltungsbereich
Diese Bedingungen gelten für die Nutzung des Discord-Bots **IronShield** sowie dieser Support-Webseite.

## 2. Nutzung des Dienstes
IronShield stellt Moderations-, Sicherheits- und Verwaltungsfunktionen für Discord-Server zur Verfügung. Die Nutzung erfolgt über das Chat-System von Discord und im Rahmen der dort offiziell geltenden Nutzungsbedingungen sowie — für Support-Anfragen — über diese Support-Webseite.

## 3. Verbotene Nutzung
Untersagt ist insbesondere:
- Missbrauch oder bewusste Störung des Bots
- Umgehung von Sicherheitsfunktionen
- Spam, Massennutzung oder automatisierte Angriffe auf unsere Systeme
- Übermäßige Belastung (z. B. durch Umgehung von Rate-Limits, API-Spam oder Nutzung durch externe automatisierte Skripte)
- Rechtswidrige Nutzung oder die Unterstützung/Bewerbung rechtswidriger Inhalte
- Manipulation, Reverse Engineering oder unbefugter Zugriff auf den Code

### Maßnahmen bei Verstößen
Bei Verstößen gegen diese Bestimmungen können je nach Schwere des Verstoßes folgende Maßnahmen ergriffen werden:
- Einschränkung einzelner Bot-Funktionen
- Temporäre Sperre der Nutzung
- Dauerhafte Sperrung eines Servers oder eines bestimmten Nutzers
- Automatische Entfernung des Bots von betroffenen Servern

## 4. Verfügbarkeit
Es besteht kein Anspruch auf eine permanente Verfügbarkeit oder Fehlerfreiheit des Bots. Die Server können für Wartungsarbeiten oder Upgrades temporär offline gehen.

## 5. Notfallzugriff auf Sicherheitssysteme
(1) Bei einer akuten Gefahr für einen Server, insbesondere bei einem Raid, einem Nuke-Versuch, einem kompromittierten Administrator-Konto oder einer Fehlkonfiguration der Schutzmodule, können die Betreiber von IronShield auf die Sicherheitssysteme des Bots für diesen Server zugreifen. Dazu gehören etwa Anti-Raid, Anti-Nuke, Lockdown, AutoMod, Verifizierung und Quarantäne.

(2) Ein solcher Zugriff erfolgt nur mit vorheriger Genehmigung des Server-Eigentümers oder eines von ihm dazu bevollmächtigten Administrators. Die Genehmigung kann formlos erteilt werden, zum Beispiel in einem Support-Ticket oder per Direktnachricht, und ist jederzeit widerruflich.

(3) Der Zugriff beschränkt sich auf das, was zur Abwehr der Gefahr erforderlich ist.

## 6. Haftung
Die Nutzung von IronShield erfolgt auf eigenes Risiko. Die Betreiber haften nur im gesetzlich zwingend vorgeschriebenen Umfang.

## 7. Änderungen
Die Betreiber behalten sich das Recht vor, die bereitgestellten Funktionen des Bots sowie diese Nutzungsbedingungen jederzeit anzupassen.

## 8. Schlussbestimmungen
Für sämtliche Rechtsbeziehungen gilt ausschließlich das Recht der Republik Österreich.
TERMS,
    ],
    'impressum' => [
        'title' => 'Impressum',
        'updated' => '',
        'text' => <<<'IMPRINT'
## Angaben gemäß § 5 DDG / § 24 Mediengesetz

### Gemeinsam Verantwortliche nach Art. 26 DSGVO für IronShield
**Sebastian Stephan**
Ollersdorferstraße 13
2261 Angern an der March
Österreich
E-Mail: ironshield.sebi@outlook.com
Telefon: +43 677 64305512

**Levi Markewski**
Heußstraße 38
70794 Filderstadt
Deutschland
E-Mail: ironshield.levi@outlook.de
Telefon: +49 152 33549222

## Discord-Support
Du erreichst uns für Support-Anfragen direkt auf unserem Discord-Server unter:
https://discord.gg/X5RPVKpFER

## Hinweis
Dieses Impressum gilt für den Discord-Bot IronShield, diese Support-Webseite sowie für alle zugehörigen offiziellen Kommunikations- und Supportkanäle.
IMPRINT,
    ],
];

$page = (string)($_GET['seite'] ?? 'datenschutz');
if (!isset($documents[$page])) $page = 'datenschutz';
$document = $documents[$page];
[$content, $toc] = legal_render($document['text']);
?><!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#090c11" />
  <title><?= htmlspecialchars($document['title'], ENT_QUOTES, 'UTF-8') ?> — Iron Shield</title>
  <link rel="icon" type="image/webp" href="/assets/bot-logo.webp?v=20261001-ticketthreads1" />
  <link rel="stylesheet" href="/assets/styles.css?v=20261001-ticketthreads1" />
</head>
<body class="legal-body">
  <header class="site-header legal-header">
    <a class="brand" href="/" aria-label="Iron Shield Startseite"><span class="brand-mark"><img src="/assets/bot-logo.webp?v=20261001-ticketthreads1" alt="" /></span><span class="brand-name">IRON<span>SHIELD</span></span></a>
    <nav class="legal-nav" aria-label="Rechtliche Informationen"><a href="/includes/recht.php?seite=datenschutz">Datenschutz</a><a href="/includes/recht.php?seite=nutzungsbedingungen">Nutzungsbedingungen</a><a href="/includes/recht.php?seite=impressum">Impressum</a></nav>
  </header>
  <main id="top" class="legal-main section-wrap">
    <div class="legal-hero"><div class="eyebrow"><span class="status-dot"></span> IRON SHIELD · RECHTLICHE INFORMATIONEN</div><h1><?= htmlspecialchars($document['title'], ENT_QUOTES, 'UTF-8') ?><span>.</span></h1><?php if ($document['updated'] !== ''): ?><p>Zuletzt aktualisiert: <?= htmlspecialchars($document['updated'], ENT_QUOTES, 'UTF-8') ?></p><?php endif; ?></div>
    <div class="legal-layout">
      <?php if ($toc): ?><aside class="legal-toc"><span>AUF DIESER SEITE</span><?php foreach ($toc as $item): ?><a href="#<?= htmlspecialchars($item['id'], ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($item['title'], ENT_QUOTES, 'UTF-8') ?></a><?php endforeach; ?></aside><?php endif; ?>
      <article class="legal-content"><?= $content ?></article>
    </div>
    <a class="legal-back" href="/">← Zurück zu Iron Shield</a>
  </main>
  <footer class="site-footer section-wrap legal-footer"><a class="brand footer-brand" href="/"><span class="brand-mark"><img src="/assets/bot-logo.webp?v=20261001-ticketthreads1" alt="" /></span><span class="brand-name">IRON<span>SHIELD</span></span></a><nav class="footer-legal"><a href="/includes/recht.php?seite=datenschutz">Datenschutz</a><a href="/includes/recht.php?seite=nutzungsbedingungen">Nutzungsbedingungen</a><a href="/includes/recht.php?seite=impressum">Impressum</a></nav><a class="back-top" href="#top">NACH OBEN <span>↑</span></a></footer>
</body>
</html>
