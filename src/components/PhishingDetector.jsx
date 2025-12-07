
import { useState, useRef, useEffect } from 'react';
import { Send, Shield } from 'lucide-react';


const PhishingDetector = () => {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: " Bonjour ! Je suis votre assistant avancé de détection de phishing alimenté par l'IA.\n\n 🔍 Analyses disponibles : \n• URLs suspectes et raccourcisseurs\n• Langage d'urgence ou menaçant\n• Demandes d'informations sensibles\n• Adresses email non standards\n• Domaines malveillants\n• En-têtes d'email (SPF, DKIM, DMARC)\n• Threat Intelligence (VirusTotal, URLhaus, OpenPhish)\n\n 📧 Comment utiliser :\n1. Collez le contenu de l'email\n2. Ou collez les en-têtes complets (Afficher l'original dans Gmail/Outlook)\n3. Décrivez le contenu de votre email"
    }
  ]);
  const [input, setInput] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [threatIntelData, setThreatIntelData] = useState(null);
  const messagesEndRef = useRef(null);

  const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:3001';

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  // Charger les données de threat intelligence du backend
  useEffect(() => {
    const loadThreatIntel = async () => {
      try {
        const response = await fetch(`${BACKEND_URL}/api/threat-intel`);
        if (response.ok) {
          const result = await response.json();
          setThreatIntelData(result.data);
          console.log('✓ Threat Intel chargées depuis le backend:', result.data.stats);
        } else {
          console.error('Erreur lors du chargement threat intel');
        }
      } catch (error) {
        console.error('Erreur connexion backend threat intel:', error);
      }
    };

    loadThreatIntel();
  }, [BACKEND_URL]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);


  // Fallback: base de données de domaines malveillants statique (si backend ne répond pas)
  const defaultMaliciousDomains = [
    'bit.ly', 'tinyurl.com', 'ow.ly', 'goo.gl', 'short.link', 't.co',
    'paypa1.com', 'paypal-secure.com', 'paypal-verify.com',
    'amazon-security.com', 'amazon-update.com', 'amaz0n.com',
    'netflix-payment.com', 'netfliix.com', 'netflix-billing.com',
    'microsoft-verify.com', 'micros0ft.com', 'windows-update.net',
    'apple-id-verify.com', 'appleid-secure.com', 'icloud-verify.com',
    'secure-banking.net', 'account-verify.net', 'update-account.com',
    'fb-security.com', 'facebook-verify.com', 'instagram-help.net'
  ];

  // Utiliser les données du backend si disponibles, sinon fallback
  const maliciousDomains = threatIntelData?.maliciousDomains || defaultMaliciousDomains;
  const maliciousUrls = threatIntelData?.openphishUrls || [];
  

  // Mots-clés suspects (pour analyse textuelle - peut rester en dur)
  const defaultSuspiciousKeywords = {
    urgence: ['urgent', 'immédiatement', 'dans les 24h', 'dernier avertissement', 
              'action requise', 'dernière chance', 'expiré', 'expire bientôt',
              'maintenant', 'tout de suite', 'sans délai'],
    menace: ['suspendu', 'bloqué', 'fermé', 'désactivé', 'annulé', 'terminé',
             'restreint', 'limité', 'verrouillé', 'sanctions', 'pénalités'],
    sensible: ['mot de passe', 'carte bancaire', 'numéro de carte', 'cvv', 
               'code pin', 'sécurité sociale', 'données personnelles', 'identifiant',
               'code secret', 'vérification', 'authentification', 'coordonnées bancaires'],
    recompense: ['gagné', 'prix', 'gratuit', 'remboursement', 'cadeau', 
                 'offre exclusive', 'promotion', 'récompense', 'bonus']
  };

  const suspiciousKeywords = threatIntelData?.suspiciousKeywords || defaultSuspiciousKeywords;

  // analyse des en-têtes d'email
  const analyzeEmailHeaders = (emailContent) => {
    const headers = {
      spf: { status: 'unknown', details: '' },
      dkim: { status: 'unknown', details: '' },
      dmarc: { status: 'unknown', details: '' },
      receivedFrom: [],
      returnPath: '',
      mismatch: false
    };

    const lines = emailContent.split('\n'); // les lignes des en-têtes dans un tableau
    
    
    const spfLine = lines.find(l => l.toLowerCase().includes('received-spf:') || l.toLowerCase().includes('spf='));
    if (spfLine) {
      if (spfLine.toLowerCase().includes('pass')) {
        headers.spf = { status: 'pass', details: 'SPF vérifié ✓' };
      } else if (spfLine.toLowerCase().includes('fail')) {
        headers.spf = { status: 'fail', details: 'SPF échoué ✗ - Serveur non autorisé' };
      } else if (spfLine.toLowerCase().includes('softfail')) {
        headers.spf = { status: 'softfail', details: 'SPF soft-fail ⚠ - Suspect' };
      } else if (spfLine.toLowerCase().includes('neutral')) {
        headers.spf = { status: 'neutral', details: 'SPF neutre - Non conclusif' };
      }
    }

    
    const dkimLine = lines.find(l => l.toLowerCase().includes('dkim-signature:') || l.toLowerCase().includes('dkim='));
    if (dkimLine) {
      if (emailContent.toLowerCase().includes('dkim=pass')) {
        headers.dkim = { status: 'pass', details: 'DKIM vérifié ✓ - Signature valide' };
      } else if (emailContent.toLowerCase().includes('dkim=fail')) {
        headers.dkim = { status: 'fail', details: 'DKIM échoué ✗ - Signature invalide' };
      } else {
        headers.dkim = { status: 'present', details: 'DKIM présent mais statut inconnu' };
      }
    }

    
    const dmarcLine = lines.find(l => l.toLowerCase().includes('dmarc='));
    if (dmarcLine) {
      if (dmarcLine.toLowerCase().includes('pass')) {
        headers.dmarc = { status: 'pass', details: 'DMARC validé ✓' };
      } else if (dmarcLine.toLowerCase().includes('fail')) {
        headers.dmarc = { status: 'fail', details: 'DMARC échoué ✗' };
      }
    }

    // Extraction Return-Path et From pour détecter les mismatches
    const returnPathLine = lines.find(l => l.toLowerCase().startsWith('return-path:'));
    const fromLine = lines.find(l => l.toLowerCase().startsWith('from:'));
    
    if (returnPathLine) {
      const returnPathMatch = returnPathLine.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i); // regex email + match : chercher la 1ére occurrence
      if (returnPathMatch) headers.returnPath = returnPathMatch[0]; // stocker l’adresse email complète dans headers.returnPath
    }

    if (fromLine && headers.returnPath) {
      const fromMatch = fromLine.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i); 
      if (fromMatch && fromMatch[0]) { // fromMatch[0] est l'adresse de 'From' affiché dans l'email -l'utilisateur final la voit
        const fromDomain = fromMatch[0].split('@')[1];
        const returnDomain = headers.returnPath.split('@')[1]; // domaine de l’adresse dans Return-Path - une adresse technique asurant la livraison par le serveur
        if (fromDomain !== returnDomain) {
          headers.mismatch = true; // un mismatch peut etre un indicateur de spoofing/redirection
        }
      }
    }

    // extraction des serveurs Received par lesquels l'email est passé
    const receivedLines = lines.filter(l => l.toLowerCase().startsWith('received:')); // chaque serveur SMTP qui relaye le message ajoute une ligne Received - la plus haute est la plus récente, serveur le plus proche du destinataire
    headers.receivedFrom = receivedLines.map(l => { // parcourir chaque ligne Received pour extraire le serveur d'envoi - suit le mot 'from'
      const match = l.match(/from\s+([^\s]+)/i); // ([^\s]+) capturant un ou plus caractères non espaces après 'from '
      return match ? match[1] : '';
    }).filter(Boolean).slice(0, 3);

    return headers;
  };

  const analyzeEmailLocally = (emailContent) => {

    const results = {
      urlSuspects: [],
      urgenceDetectee: false,
      menaceDetectee: false,
      infoSensibleDemandee: false,
      domainesMalveillants: [],
      emailNonStandard: false,
      score: 0,
      headers: null,
      hasHeaders: false
    };

    const lowerContent = emailContent.toLowerCase();

    // détecter si ce sont des en-têtes d'email

    if (lowerContent.includes('received:') || lowerContent.includes('dkim-signature:') || 
        lowerContent.includes('return-path:')) {
      results.hasHeaders = true;
      results.headers = analyzeEmailHeaders(emailContent);      
      // scoring basé sur les en-têtes - local sans IA
      if (results.headers.spf.status === 'fail') results.score += 25;
      if (results.headers.spf.status === 'softfail') results.score += 15;
      if (results.headers.dkim.status === 'fail') results.score += 25;
      if (results.headers.dmarc.status === 'fail') results.score += 30;
      if (results.headers.mismatch) results.score += 20;
    }

    // analyse des URLs

    const urlRegex = /(https?:\/\/[^\s]+)/g;
    const urls = emailContent.match(urlRegex) || [];
    
    results.extractedUrls = urls;
    
    urls.forEach(url => {
      const domain = url.split('/')[2];

      // Vérifier si l'URL complète est dans OpenPhish
      if (maliciousUrls.includes(url)) {
        results.urlSuspects.push(url);
        results.domainesMalveillants.push(domain);
        results.score += 40;
      }
      
      // Vérifier si le domaine est malveillant (URLhaus, OpenPhish extraits)
      if (maliciousDomains.some(md => domain?.toLowerCase().includes(md.toLowerCase()))) {
        if (!results.urlSuspects.includes(url)) {
          results.urlSuspects.push(url);
        }
        if (!results.domainesMalveillants.includes(domain)) {
          results.domainesMalveillants.push(domain);
        }
        results.score += 35;
      }
      
      // détection de raccourcisseurs

      const shorteners = [ 
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'buff.ly', 'is.gd', 'cutt.ly',
        'bit.do', 'mcaf.ee', 'rebrand.ly', 'tiny.cc', 'soo.gd', 'qr.ae', 'v.gd',
        'shorte.st', 'adf.ly', 't.ly', 'smarturl.it', 'yourls.org', 'trib.al',
        'rb.gy', 'bl.ink', 's.id', 'lnkd.in', 'snip.ly', 'po.st', 'shorturl.at',
        'clck.ru', 'cutt.us', 'lc.chat', '1url.com', 'ulvis.net', 'capsulink.com',
        'hyperurl.co', 'l.wl.co', 'v.ht', 't2m.io', 'git.io', 'gg.gg', 'x.co',
        'fur.ly', 'ity.im', 'ow.ly', 's7y.us', 'tny.im', 'linktr.ee', 'tinvurl.net'
      ];

      if (shorteners.some(s => domain?.includes(s))) {
        results.score += 20;
      }
      
      // détection d'IP dans l'URL (très suspect)

      if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
        results.score += 35;
      }
    });

    // analyse du langage d'urgence

    if (suspiciousKeywords.urgence.some(k => lowerContent.includes(k))) {
      results.urgenceDetectee = true;
      results.score += 15;
    }

    // analyse du langage menaçant

    if (suspiciousKeywords.menace.some(k => lowerContent.includes(k))) {
      results.menaceDetectee = true;
      results.score += 20;
    }

    // demande d'informations sensibles

    if (suspiciousKeywords.sensible.some(k => lowerContent.includes(k))) {
      results.infoSensibleDemandee = true;
      results.score += 25;
    }

    // analyse du langage de récompense

    if (suspiciousKeywords.recompense.some(k => lowerContent.includes(k))) {
      results.urgenceDetectee = true;
      results.score += 5;
    }

    // email non standard

    const emailRegex = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
    const emails = emailContent.match(emailRegex) || [];
    emails.forEach(email => {
      if (email.includes('noreply') || email.match(/\d{5,}/)) { // adresse avec 'noreply' ou chiffres longs
        results.emailNonStandard = true;
        results.score += 10;
      }
    });

    return results;
  };

  // Analyse avancée avec l'IA via le backend proxy
  const analyzeWithAI = async (emailContent, localAnalysis) => { 
    try {
      const response = await fetch(`${BACKEND_URL}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          emailContent: emailContent,
          localAnalysis
        })
      });      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Erreur ${response.status}`);
      }

      const result = await response.json();
      return result;
      
    } catch (error) {
      console.error('Backend API Error:', error);
      return { 
        error: `Analyse IA échouée: ${error.message}`,
        fallbackAnalysis: 'Service IA indisponible. Affichage de l\'analyse locale uniquement.'
      };
    }
  };

  const formatAnalysisResult = (localAnalysis, aiAnalysis) => {
    let result = '📊 RÉSULTATS DE L\'ANALYSE AVANCÉE:\n\n';

    if (aiAnalysis && !aiAnalysis.error) {
      result += `🎯 Verdict IA: ${aiAnalysis.isPhishing ? '🚨 PHISHING DÉTECTÉ' : '✅ Email semble légitime'}\n`;
      result += `📈 Confiance: ${aiAnalysis.confidence}%\n\n`;
      
      if (aiAnalysis.risks && aiAnalysis.risks.length > 0) {
        result += `⚠️ Risques identifiés:\n`;
        aiAnalysis.risks.forEach(risk => result += `  • ${risk}\n`);
        result += '\n';
      }

      result += `💡 Analyse: ${aiAnalysis.explanation || 'Non disponible'}\n\n`;
    } else if (aiAnalysis?.error) {
      result += `❌ Erreur d'analyse IA: ${aiAnalysis.error}\n\n`;
    }

    // En-têtes d'email
    if (localAnalysis.hasHeaders && localAnalysis.headers) {
      result += `📧 ANALYSE DES EN-TÊTES EMAIL:\n`;
      result += `• SPF: ${localAnalysis.headers.spf.details}\n`;
      result += `• DKIM: ${localAnalysis.headers.dkim.details}\n`;
      result += `• DMARC: ${localAnalysis.headers.dmarc.details}\n`;
      
      if (localAnalysis.headers.mismatch) {
        result += `• ⚠️ ALERTE: Mismatch entre From et Return-Path:\n`;
        result += `  From: ${localAnalysis.headers.from}\n`;
        result += `  Return-Path: ${localAnalysis.headers.returnPath}\n`;
      }
      
      if (localAnalysis.headers.receivedFrom.length > 0) {
        result += `• Serveurs: ${localAnalysis.headers.receivedFrom.slice(0, 2).join(' → ')}\n`;
      }
      result += '\n';
    }

    result += `📋 DÉTAILS TECHNIQUES:\n`;
    result += `• Score de risque calculé: ${Math.min(localAnalysis.score, 100)}/100\n`;
    if (localAnalysis.extractedUrls?.length > 0) {
      result += `• URLs trouvées: ${localAnalysis.extractedUrls}\n`;
    }
    if (localAnalysis.urlSuspects.length > 0) {
      result += `• URLs suspectes detectés: ${localAnalysis.urlSuspects}\n`;
    }
    if (localAnalysis.domainesMalveillants.length > 0) {
      result += `• Domaines malveillants detectés: ${localAnalysis.domainesMalveillants.join(', ')}\n`;
    }
    if (localAnalysis.urgenceDetectee) result += `• ⚠️ Langage d'urgence détecté\n`;
    if (localAnalysis.menaceDetectee) result += `• ⚠️ Langage menaçant détecté\n`;
    if (localAnalysis.infoSensibleDemandee) result += `• 🔒 Demande d'informations sensibles\n`;
    if (localAnalysis.emailNonStandard) result += `• 📧 Adresse email non-standard détectée\n`;

      
      if (aiAnalysis?.threatIntel) {
        result += `\n🛡️ THREAT INTELLIGENCE:\n`;
      
        // OpenPhish
        if (aiAnalysis.threatIntel.openphish) {
          result += `📌 OpenPhish (Phishing URLs Database):\n`;
          result += `  • Statut: ${aiAnalysis.threatIntel.openphish.status === 'detected' ? '🚨 DÉTECTÉ' : '✓ Non détecté'}\n`;
          result += `  • ${aiAnalysis.threatIntel.openphish.message}\n`;
        }
      
        // URLhaus
        if (aiAnalysis.threatIntel.urlhaus) {
          result += `🌐 URLhaus (Malicious URLs):\n`;
          result += `  • Statut: ${aiAnalysis.threatIntel.urlhaus.status === 'malicious' ? '🚨 MALVEILLANT' : '✓ Propre'}\n`;
          result += `  • ${aiAnalysis.threatIntel.urlhaus.message}\n`;
        }
      
        // VirusTotal
        if (aiAnalysis.threatIntel.virustotal) {
          result += `🔬 VirusTotal (URL Reputation):\n`;
          const vt = aiAnalysis.threatIntel.virustotal;
          if (vt.error) {
            result += `  • Erreur: ${vt.error}\n`;
          } else if (vt.status === 'submitted') {
            result += `  • ⏳ ${vt.message}\n`;
          } else {
            result += `  • Détections malveillantes: ${vt.malicious || 0}/${vt.total || 0}\n`;
            result += `  • Détections suspectes: ${vt.suspicious || 0}\n`;
            result += `  • Détections inoffensives: ${vt.harmless || 0}\n`;
            result += `  • Non détectées: ${vt.undetected || 0}\n`;
            result += `  • Réputation: ${vt.reputation || 0}\n`;
          }
        }
        result += '\n';
      }

    if (aiAnalysis?.recommendations?.length > 0) {
      result += `\n🛡️ RECOMMANDATIONS:\n`;
      aiAnalysis.recommendations.forEach(rec => result += `  • ${rec}\n`);
    }

    return result;
  };

  // soumission de l'analyse

  const handleSubmit = async (e) => {
    e?.preventDefault();
    if (!input.trim() || isAnalyzing) return;

    const userMessage = { role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsAnalyzing(true);

    // Analyse locale
    const localAnalysis = analyzeEmailLocally(input);

    // Message de progression
    setMessages(prev => [...prev, {
      role: 'assistant',
      content: '🔍 ANALYSE EN COURS...\n\n✓ Scan des URLs et domaines\n✓ Détection des patterns suspects\n' + 
               (localAnalysis.hasHeaders ? '✓ Analyse des en-têtes (SPF/DKIM/DMARC)\n' : '') +
               (localAnalysis.extractedUrls?.length > 0 ? '✓ Consultation Threat Intelligence (OpenPhish/URLhaus/VirusTotal)\n' : '') +
               '⏳ Consultation de l\'IA avancée...'
    }]);

    // Analyse IA (backend enrichit automatiquement avec threat intel)
    const aiAnalysis = await analyzeWithAI(input, localAnalysis);

    // Résultats finaux
    setMessages(prev => {
      const newMessages = [...prev];
      newMessages[newMessages.length - 1] = {
        role: 'assistant',
        content: formatAnalysisResult(localAnalysis, aiAnalysis)
      };
      return newMessages;
    });

    setIsAnalyzing(false);
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    }}>
      {/* Header */}
      <div style={{
        background: 'rgba(255, 255, 255, 0.95)',
        padding: '20px',
        boxShadow: '0 2px 10px rgba(0,0,0,0.1)',
        borderBottom: '3px solid #667eea'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
            <Shield size={32} color="#667eea" />
            <div>
              <h1 style={{ margin: 0, fontSize: '24px', color: '#333' }}>
                Détecteur de Phishing Avancé
              </h1>              
            </div>
          </div>
        </div>

        
      </div>

      {/* Messages */}
      <div style={{ 
        flex: 1,
        overflowY: 'auto',
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '15px'
      }}>
        {messages.map((msg, idx) => (
          <div
            key={idx}
            style={{
              display: 'flex',
              justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start'
            }}
          >
            <div style={{
              maxWidth: '85%',
              padding: '15px 20px',
              borderRadius: '15px',
              background: msg.role === 'user' 
                ? 'linear-gradient(135deg, #1c2138ff 0%, #435dbcff 100%)'
                : 'rgba(255, 255, 255, 0.95)',
              color: msg.role === 'user' ? 'white' : '#333',
              boxShadow: '0 2px 8px rgba(0,0,0,0.15)',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              fontSize: '15px',
              lineHeight: '1.6'
            }}>
              {msg.content}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div style={{
        padding: '20px',
        background: 'rgba(255, 255, 255, 0.95)',
        borderTop: '1px solid #e0e0e0'
      }}>
        <div style={{
          display: 'flex',
          gap: '10px',
          maxWidth: '1200px',
          margin: '0 auto'
        }}>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={(e) => {
              if (e.key === 'Enter' && !e.shiftKey && !isAnalyzing && input.trim()) {
                e.preventDefault();
                handleSubmit();
              }
            }}
            placeholder="Collez le contenu de l'email ou les en-têtes complets (Afficher l'original)..."
            disabled={isAnalyzing}
            rows="3"
            style={{
              flex: 1,
              padding: '15px',
              border: '2px solid #e0e0e0',
              borderRadius: '10px',
              fontSize: '16px',
              outline: 'none',
              transition: 'border-color 0.3s',
              resize: 'vertical',
              fontFamily: 'inherit'
            }}
            onFocus={(e) => e.target.style.borderColor = '#8797daff'}
            onBlur={(e) => e.target.style.borderColor = '#e0e0e0'}
          />
          <button
            onClick={handleSubmit}
            disabled={isAnalyzing || !input.trim()}
            style={{
              padding: '15px 30px',
              background: isAnalyzing ? '#ccc' : 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              color: 'white',
              border: 'none',
              borderRadius: '10px',
              cursor: isAnalyzing ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              fontSize: '16px',
              fontWeight: 'bold',
              transition: 'transform 0.2s',
              boxShadow: '0 4px 12px rgba(102, 126, 234, 0.4)',
              height: 'fit-content'
            }}
            onMouseOver={(e) => !isAnalyzing && (e.target.style.transform = 'scale(1.05)')}
            onMouseOut={(e) => e.target.style.transform = 'scale(1)'}
          >
            {isAnalyzing ? 'Analyse...' : 'Analyser'}
            <Send size={20} />
          </button>
        </div>
      </div>

      {/* Info Footer */}
      <div style={{
        background: 'rgba(255, 255, 255, 0.9)',
        padding: '10px 20px',
        textAlign: 'center',
        fontSize: '12px',
        color: '#666',
        borderTop: '1px solid #e0e0e0'
      }}>
        🔒 Analyse en temps réel • Aucune donnée stockée • Analyse SPF/DKIM/DMARC • Propulsé par Meta Llama 3 + VirusTotal + URLhaus + OpenPhish
      </div>
    </div>
  );
};

export default PhishingDetector;