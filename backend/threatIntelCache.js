const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');

const CACHE_DIR = path.join(__dirname, 'cache');
const CACHE_EXPIRY = 24 * 60 * 60 * 1000; // 24 heures

// Créer le dossier cache s'il n'existe pas

if (!fs.existsSync(CACHE_DIR)) {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
}

const cacheFile = path.join(CACHE_DIR, 'threat-intel.json');


// Charge les données de cache depuis le disque

const loadCache = () => {
  try {
    if (fs.existsSync(cacheFile)) {
      const data = fs.readFileSync(cacheFile, 'utf-8');
      return JSON.parse(data);
    }
  } catch (err) {
    console.error('Erreur lors du chargement du cache:', err.message);
  }
  return null;
};


// Sauvegarde le cache sur le disque
 
const saveCache = (data) => {
  try {
    fs.writeFileSync(cacheFile, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Erreur lors de la sauvegarde du cache:', err.message);
  }
};


// Vérifie si le cache est encore valide
 
const isCacheValid = () => {
  try {
    if (!fs.existsSync(cacheFile)) return false;
    const stats = fs.statSync(cacheFile);
    const now = Date.now();
    return (now - stats.mtime.getTime()) < CACHE_EXPIRY;
  } catch (err) {
    return false;
  }
};


// Récupère les URLs de phishing d'OpenPhish)

const fetchOpenPhishData = async () => {
  try {
    console.log('Chargement des URLs depuis OpenPhish...');
    const response = await fetch('https://openphish.com/feed.txt', {
      timeout: 10000
    });
    
    if (!response.ok) {
      throw new Error(`OpenPhish HTTP ${response.status}`);
    }

    const text = await response.text();
    const urls = text
      .split('\n')
      .map(url => url.trim())
      .filter(url => url.length > 0 && (url.startsWith('http://') || url.startsWith('https://')));
    
    console.log(`Chargement des URLs depuis OpenPhish: ${urls.length} URLs chargées`);
    return urls;
  } catch (err) {
    console.error('Erreur OpenPhish:', err.message);
    return [];
  }
};


// Récupère les domaines malveillants depuis URLhaus

const fetchURLhausData = async () => {
  try {
    console.log('[ThreatIntel] Chargement URLhaus...');
    // Utiliser le CSV endpoint au lieu du JSON API (moins restrictif)
    const response = await fetch('https://urlhaus.abuse.ch/downloads/csv_recent/', {
      timeout: 10000,
      headers: {
        'User-Agent': 'Mozilla/5.0'
      }
    });
    
    if (!response.ok) {
      throw new Error(`URLhaus HTTP ${response.status}`);
    }

    const text = await response.text();
    const domains = new Set();

    // Parcourir les lignes du CSV
    const lines = text.split('\n');
    lines.forEach(line => {
      if (line.startsWith('"http')) {
        try {
          // Format CSV: "url","status","date_added"
          const match = line.match(/"(https?:\/\/[^"]+)"/);
          if (match && match[1]) {
            const url = new URL(match[1]);
            if (url.hostname) {
              domains.add(url.hostname);
            }
          }
        } catch (e) {
          // URL invalide, ignorer
        }
      }
    });

    const domainList = Array.from(domains);
    console.log(`Chargement des domaines depuis URLhaus: ${domainList.length} domaines chargés`);
    return domainList;
  } catch (err) {
    console.error('Erreur URLhaus:', err.message);    
    return []; // Ne pas lever l'erreur, continuer avec les autres sources
  }
};

// Enrichissement et vérification avec VirusTotal

const checkVirusTotal = async (url) => {
  if (!process.env.VIRUSTOTAL_API_KEY) {
    return { error: 'Clé API VirusTotal non configurée' };
  }

  try {
    const urlID = Buffer.from(url).toString('base64').replace(/=/g, '');
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlID}`, {
      headers: {
        'x-apikey': process.env.VIRUSTOTAL_API_KEY
      },
      timeout: 10000
    });

    if (response.status === 404) {
      // URL non encore analysée : soumettre pour analyse
      const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': process.env.VIRUSTOTAL_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`,
        timeout: 10000
      });

      if (submitResponse.ok) {
        return { status: 'submitted', message: 'URL soumise pour analyse. Réessayez dans 30 secondes.' };
      }
    }

    if (!response.ok) {
      return { error: `VirusTotal HTTP ${response.status}` };
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats || {};

    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
      reputation: data.data.attributes.reputation || 0
    };

  } catch (err) {
    console.error('[ThreatIntel] VirusTotal error:', err.message || err);
    return { error: err.message || String(err) };
  }
};

// Liste étendue de mots-clés suspects (en francais + patterns de phishing)

const getExtendedSuspiciousKeywords = () => {
  return {
    urgence: [
      'urgent', 'immédiatement', 'dans les 24h', 'dernier avertissement',
      'action requise', 'dernière chance', 'expiré', 'expire bientôt',
      'maintenant', 'tout de suite', 'sans délai', 'rapidement',
      'asap', 'au plus tôt', 'pressure', 'temps limité', 'offre limitée',
      'avant que', 'avant de', 'avant le', 'delai court', 'vite'
    ],
    menace: [
      'suspendu', 'bloqué', 'fermé', 'désactivé', 'annulé', 'terminé',
      'restreint', 'limité', 'verrouillé', 'sanctions', 'pénalités',
      'avertissement', 'violation', 'non-conformité', 'risque', 'danger',
      'menace', 'compromis', 'frauduleux', 'illégal', 'problème de sécurité',
      'compte en danger', 'compte compromis', 'accès non autorisé',
      'activité suspecte', 'tentative de connexion'
    ],
    sensible: [
      'mot de passe', 'carte bancaire', 'numéro de carte', 'cvv',
      'code pin', 'sécurité sociale', 'données personnelles', 'identifiant',
      'code secret', 'vérification', 'authentification', 'coordonnées bancaires',
      'iban', 'bic', 'compte bancaire', 'identité', 'nip', 'code confidentiel',
      'information personnelle', 'donnée confidentielle', 'secret',
      'connexion', 'se connecter', 's\'authentifier', 'confirmer identité',
      'valider compte', 'vérifier identité', 'crédits', 'paiement'
    ],
    recompense: [
      'gagné', 'prix', 'gratuit', 'remboursement', 'cadeau',
      'offre exclusive', 'promotion', 'récompense', 'bonus', 'surprise',
      'jackpot', 'gagnant', 'grand prix', 'tirage au sort', 'concours',
      'loterie', 'bénéfice', 'avantage', 'deal', 'offre spéciale',
      'reduction', 'rabais', 'économies', 'c\'est gratuit', 'sans frais'
    ]
  };
};


// Récupère ou met à jour toutes les données de threat intelligence de URLhaus et OpenPhish
 
const getThreatIntelData = async (forceRefresh = false) => {

  // Vérifier le cache

  if (!forceRefresh && isCacheValid()) {
    const cachedData = loadCache();
    if (cachedData) {
      console.log('Utilisation du cache valide');
      return cachedData;
    }
  }

  console.log('Mise à jour des données...');

  const [openphishUrls, urlhausDomains] = await Promise.all([
    fetchOpenPhishData(),
    fetchURLhausData()
  ]);

  // Base de données locale (domaines courants de typo-squats + raccourcisseurs)

  const localMaliciousDomains = [
    'bit.ly', 'tinyurl.com', 'ow.ly', 'goo.gl', 'short.link', 't.co',
    'paypa1.com', 'paypal-secure.com', 'paypal-verify.com', 'paypa1-secure.com',
    'amazon-security.com', 'amazon-update.com', 'amaz0n.com', 'amazonsecure.net',
    'netflix-payment.com', 'netfliix.com', 'netflix-billing.com', 'netflix-confirm.com',
    'microsoft-verify.com', 'micros0ft.com', 'windows-update.net', 'microsoftverify.com',
    'apple-id-verify.com', 'appleid-secure.com', 'icloud-verify.com', 'apple-secure.net',
    'secure-banking.net', 'account-verify.net', 'update-account.com', 'verify-account.net',
    'fb-security.com', 'facebook-verify.com', 'instagram-help.net', 'facebook-login.com',
    'google-security.com', 'google-verify.com', 'gmail-secure.net', 'accounts-google.com'
  ];

  // Combiner toutes les listes de domaines malveillants

  const allMaliciousDomains = [
    ...localMaliciousDomains,
    ...urlhausDomains,
    ...openphishUrls.map(url => {
      try {
        return new URL(url).hostname;
      } catch {
        return null;
      }
    }).filter(Boolean)
  ];

  
  const uniqueDomains = Array.from(new Set(allMaliciousDomains)); // Dédupliquer la liste des domaines


  const threatIntelData = {
    maliciousDomains: uniqueDomains,
    openphishUrls: openphishUrls,
    suspiciousKeywords: getExtendedSuspiciousKeywords(),
    lastUpdated: new Date().toISOString(),
    stats: {
      totalMaliciousDomains: uniqueDomains.length,
      openphishUrls: openphishUrls.length,
      urlhausDomains: urlhausDomains.length,
      localDomains: localMaliciousDomains.length
    }
  };

  // Sauvegarder le cache les nouvelles données de threat intel
  saveCache(threatIntelData);

  console.log('Données ThreatIntel mises à jour:', threatIntelData.stats);
  return threatIntelData;
};


// Vérifie si un domaine est malveillant

const isDomainMalicious = async (domain, threatIntelData) => {
  if (!threatIntelData) {
    threatIntelData = await getThreatIntelData();
  }

  const cleanDomain = domain.toLowerCase().trim();
  
  // Vérification exacte
  if (threatIntelData.maliciousDomains.includes(cleanDomain)) {
    return true;
  }

  // Vérification si c'est un sous-domaine
  for (const malicious of threatIntelData.maliciousDomains) {
    if (cleanDomain.endsWith('.' + malicious) || cleanDomain === malicious) { 
      return true;
    }
  }

  return false;
};

module.exports = {
  getThreatIntelData,
  isDomainMalicious,
  isCacheValid,
  loadCache,
  saveCache,
  checkVirusTotal
};
