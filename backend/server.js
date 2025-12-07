require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { getThreatIntelData, isDomainMalicious, isCacheValid, checkVirusTotal } = require('./threatIntelCache');

const app = express();
const PORT = process.env.PORT || 3001;
let threatIntelCache = null;

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limite de chaque IP à 100 requêtes par windowMs
  message: { error: 'Trop de requêtes, veuillez réessayer plus tard.' }
});

app.use('/api/', limiter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), 
    threatIntelCacheLoaded: threatIntelCache !== null});
});

// Route pour récupérer les données de threat intelligence
app.get('/api/threat-intel', async (req, res) => {
  try {
    const forceRefresh = req.query.refresh === 'true';
    
    if (!threatIntelCache || forceRefresh) {
      threatIntelCache = await getThreatIntelData(forceRefresh);
    }
    // Envoyer les données de threat intelligence au frontend: malicious domains depuis URLhaus et OpenPhish et urls OpenPhish
    res.json({
      status: 'ok',
      data: {
        maliciousDomains: threatIntelCache.maliciousDomains,
        suspiciousKeywords: threatIntelCache.suspiciousKeywords,
        stats: threatIntelCache.stats,
        lastUpdated: threatIntelCache.lastUpdated,
        cacheValid: isCacheValid()
      }
    });
  } catch (error) {
    console.error('ThreatIntel Error:', error);
    res.status(500).json({
      error: 'Erreur lors du chargement des données de threat intelligence',
      message: error.message
    });
  }
});

// Route pour vérifier si un domaine est malveillant
app.post('/api/threat-intel/check-domain', async (req, res) => {
  try {
    const { domain } = req.body;

    if (!domain || typeof domain !== 'string') {
      return res.status(400).json({ error: 'Domaine invalide' });
    }

    if (!threatIntelCache) {
      threatIntelCache = await getThreatIntelData();
    }

    const isMalicious = await isDomainMalicious(domain, threatIntelCache);

    res.json({
      domain: domain,
      isMalicious: isMalicious,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Check Domain Error:', error);
    res.status(500).json({
      error: 'Erreur lors de la vérification du domaine',
      message: error.message
    });
  }
});

// Route pour forcer la mise à jour du cache
app.post('/api/threat-intel/refresh', async (req, res) => {
  try {
    console.log('Actualisation forcée du cache threat intel...');
    threatIntelCache = await getThreatIntelData(true);
    
    res.json({
      status: 'ok',
      message: 'Cache mis à jour avec succès',
      stats: threatIntelCache.stats,
      lastUpdated: threatIntelCache.lastUpdated
    });
  } catch (error) {
    console.error('Refresh Error:', error);
    res.status(500).json({
      error: 'Erreur lors de la mise à jour',
      message: error.message
    });
  }
});


// Endpoint proxy pour Groq API avec enrichissement Threat Intelligence centralisé
app.post('/api/analyze', async (req, res) => {
  try {
    const { emailContent, localAnalysis } = req.body;

    if (!emailContent || emailContent.trim().length === 0) {
      return res.status(400).json({ error: 'Contenu email manquant' });
    }

    if (emailContent.length > 50000) {
      return res.status(400).json({ error: 'Contenu trop long (max 50KB)' });
    }

    // Charger le cache threat intel si nécessaire
    if (!threatIntelCache) {
      threatIntelCache = await getThreatIntelData();
    }

    // === Enrichissement Threat Intelligence côté backend ===
    const threatIntelResults = {
      virustotal: null,
      urlhaus: null,
      openphish: null
    };


    if (localAnalysis.extractedUrls?.length > 0) {
      const firstUrl = localAnalysis.extractedUrls[0];
      
      // Vérifier si URL est dans OpenPhish
      if (threatIntelCache.openphishUrls?.includes(firstUrl)) {
        threatIntelResults.openphish = { 
          status: 'detected',
          message: 'URL détectée dans OpenPhish (base de phishing)'
        };
      } else {
        threatIntelResults.openphish = { 
          status: 'clean',
          message: 'URL non trouvée dans OpenPhish'
        };
      }

      // Vérifier domaine avec isDomainMalicious (URLhaus + local)
      const domain = firstUrl.split('/')[2];
      if (domain) {
        const isMalicious = await isDomainMalicious(domain, threatIntelCache);
        if (isMalicious) {
          threatIntelResults.urlhaus = {
            status: 'malicious',
            message: 'Domaine détecté comme malveillant (URLhaus/OpenPhish)'
          };
        } else {
          threatIntelResults.urlhaus = {
            status: 'clean',
            message: 'Domaine non malveillant'
          };
        }
      } 

      // Enrichir avec VirusTotal (réputation)
      if (process.env.VIRUSTOTAL_API_KEY) {
        try {
          threatIntelResults.virustotal = await checkVirusTotal(firstUrl);
        } catch (error) {
          console.error('⚠️ VirusTotal error:', error.message || error);
          threatIntelResults.virustotal = { error: 'Service indisponible' };
        }
      }
    }

    const prompt = `Tu es un expert en cybersécurité spécialisé dans la détection de phishing. Analyse cet email avec toutes les données disponibles et fournis une réponse en JSON strict.

Email à analyser: 
${emailContent.substring(0, 2000)} 

Analyse préliminaire:
- Nombre d'URLs extraites: ${localAnalysis.extractedUrls?.length || 0}
- URLs extraites: ${localAnalysis.extractedUrls || 'aucun'}
- Nombre d'URLs suspectes: ${localAnalysis.urlSuspects?.length || 0}
- URLs suspectes: ${localAnalysis.urlSuspects || 'aucun'}
- Domaines malveillants: ${localAnalysis.domainesMalveillants?.join(', ') || 'aucun'}
- Urgence: ${localAnalysis.urgenceDetectee}
- Menaces: ${localAnalysis.menaceDetectee}
- Infos sensibles: ${localAnalysis.infoSensibleDemandee}
- language de récompense: ${localAnalysis.languageRecompenseDetectee}
- Score local: ${localAnalysis.score}/100

${localAnalysis.hasHeaders ? `
En-têtes email:
- SPF: ${localAnalysis.headers.spf.status} - ${localAnalysis.headers.spf.details}
- DKIM: ${localAnalysis.headers.dkim.status} - ${localAnalysis.headers.dkim.details}
- DMARC: ${localAnalysis.headers.dmarc.status} - ${localAnalysis.headers.dmarc.details}
- Mismatch From/Return-Path: ${localAnalysis.headers.mismatch}
` : ''}

${threatIntelResults.openphish ? `
OpenPhish:
- URL détectée: ${threatIntelResults.openphish.message}
` : ''}

${threatIntelResults.urlhaus ? `
URLhaus:
- Domaine malveillant: ${threatIntelResults.urlhaus.message}
` : ''}

${threatIntelResults.virustotal && !threatIntelResults.virustotal.error ? `
VirusTotal:
- Détections malveillantes: ${threatIntelResults.virustotal.malicious || 0}/${threatIntelResults.virustotal.total || 0}
- Suspectes: ${threatIntelResults.virustotal.suspicious || 0}
- Réputation: ${threatIntelResults.virustotal.reputation || 0}
` : ''}

Ta mission est d'analyser cet email en profendeur en utilisant TOUS les élèments ci-dessus et de fournir UNIQUEMENT un objet JSON avec cette structure exacte:
{
  "isPhishing": true/false,
  "confidence": 0-100,
  "risks": ["risque1", "risque2"],
  "explanation": "explication détaillée avec la meme langue que l'email",
  "recommendations": ["conseil1", "conseil2"],
  "threatIntel": {
    "openphish": { "status": "detected/clean", "message": "..." },
    "urlhaus": { "status": "malicious/clean", "message": "..." },
    "virustotal": { "malicious": X, "suspicious": Y, "reputation": Z, "total": W }
  }
}`;

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          {
            role: 'system',
            content: 'Tu es un expert en cybersécurité spécialisé dans la détection et analyse des emails de Phishing. Réponds toujours en JSON valide sans markdown.'
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.1,
        response_format: { type: "json_object" }
      })
    });

    if (!response.ok) {
      const errorData = await response.text();
      console.error('Groq API Error:', response.status, errorData);
      return res.status(response.status).json({ 
        error: `Erreur API Groq: ${response.status}`,
        details: errorData
      });
    }

    const data = await response.json();
    const textContent = data.choices[0].message.content;

    try {
      const cleanJson = textContent.replace(/```json|```/g, '').trim();
      const parsedResult = JSON.parse(cleanJson);
      res.json(parsedResult);
    } catch (parseError) {
      console.error('JSON Parse Error:', parseError);
      res.status(500).json({
        error: 'Erreur de parsing JSON',
        rawContent: textContent
      });
    }

  } catch (error) {
    console.error('Server Error:', error);
    res.status(500).json({ 
      error: 'Erreur serveur interne',
      message: error.message 
    });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'Route non trouvée' });
});

app.listen(PORT, async () => {
  console.log(` Serveur proxy démarré sur le port ${PORT}`);
  console.log(` Frontend autorisé: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
  console.log(` Groq API Key configurée: ${process.env.GROQ_API_KEY ? '✓' : '✗'}`);
  
  // Charger les données de threat intelligence au démarrage
  try {
    console.log(' Chargement des données de threat intelligence...');
    threatIntelCache = await getThreatIntelData();
    console.log('✓ Threat intel chargé avec succès');
  } catch (error) {
    console.error('⚠ Erreur lors du chargement de threat intel:', error.message);
  }
});

module.exports = app;