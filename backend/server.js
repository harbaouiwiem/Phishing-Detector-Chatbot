require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { getThreatIntelData, isDomainMalicious, isCacheValid } = require('./threatIntelCache');

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
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Trop de requêtes, veuillez réessayer plus tard.' }
});

app.use('/api/', limiter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), 
  virustotal: {configured: !!process.env.VIRUSTOTAL_API_KEY}});
});

// focntion pour vérifier VirusTotal côté backend
async function checkVirusTotalBackend(url) {
  if (!process.env.VIRUSTOTAL_API_KEY) {
    throw new Error('Clé API VirusTotal non configurée');
  }

 try {
    // encoder l'URL en base64 sans padding
    const urlID = Buffer.from(url).toString('base64').replace(/=/g, '');
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlID}`, {
      headers: {
        'x-apikey': process.env.VIRUSTOTAL_API_KEY
      },
      timeout: 10000
    });

    if (response.status === 404) {
      // url pas encore scanéée, la soumettre pour analyse
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
      return { Error:`VirusTotal HTTP ${response.status}`};
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;

    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total: stats.malicious + stats.suspicious + stats.harmless + stats.undetected,
      reputation: data.data.attributes.reputation || 0
    };
  } catch (error) {console.error('VirusTotal error:', error);
    return { error: error.message };}
}

// Route pour récupérer les données de threat intelligence
app.get('/api/threat-intel', async (req, res) => {
  try {
    const forceRefresh = req.query.refresh === 'true';
    
    if (!threatIntelCache || forceRefresh) {
      threatIntelCache = await getThreatIntelData(forceRefresh);
    }

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


// Endpoint proxy pour Groq API
app.post('/api/analyze', async (req, res) => {
  try {
    const { emailContent, localAnalysis, threatIntelResults } = req.body;

    if (!emailContent || emailContent.trim().length === 0) {
      return res.status(400).json({ error: 'Contenu email manquant' });
    }

    if (emailContent.length > 50000) {
      return res.status(400).json({ error: 'Contenu trop long (max 50KB)' });
    }

   // enrichier avec VirusTotal côté backend
   if (localAnalysis.extractedUrls?.length > 0 && process.env.VIRUSTOTAL_API_KEY) {
      const firstUrl = localAnalysis.extractedUrls[0];
      try {
        threatIntelResults.virustotal = await checkVirusTotalBackend(firstUrl);
      } catch (error) {
        console.error('⚠️ VirusTotal error (continuant sans):', error.message);
        threatIntelResults.virustotal = { error: 'Service indisponible' };
        }
    }

    const prompt = `Tu es un expert en cybersécurité spécialisé dans la détection de phishing. Analyse cet email avec toutes les données disponibles et fournis une réponse en JSON strict.

Email à analyser: 
${emailContent.substring(0, 2000)} 

Analyse préliminaire:
- URLs extraites: ${localAnalysis.extractedUrls?.length || 0}
- URLs suspectes: ${localAnalysis.urlSuspects?.length || 0}
- Domaines malveillants: ${localAnalysis.domainesMalveillants?.join(', ') || 'aucun'}
- Urgence: ${localAnalysis.urgenceDetectee}
- Menaces: ${localAnalysis.menaceDetectee}
- Infos sensibles: ${localAnalysis.infoSensibleDemandee}
- Score local: ${localAnalysis.score}/100

${localAnalysis.hasHeaders ? `
En-têtes email:
- SPF: ${localAnalysis.headers.spf.status} - ${localAnalysis.headers.spf.details}
- DKIM: ${localAnalysis.headers.dkim.status} - ${localAnalysis.headers.dkim.details}
- DMARC: ${localAnalysis.headers.dmarc.status} - ${localAnalysis.headers.dmarc.details}
- Mismatch From/Return-Path: ${localAnalysis.headers.mismatch}
` : ''}

${threatIntelResults.virustotal ? `
VirusTotal:
- Détections malveillantes: ${threatIntelResults.virustotal.malicious}/${threatIntelResults.virustotal.total}
- Suspectes: ${threatIntelResults.virustotal.suspicious}
- Réputation: ${threatIntelResults.virustotal.reputation}
` : ''}

${threatIntelResults.urlhaus ? `
URLhaus:
- Statut: ${threatIntelResults.urlhaus.status}
- Menace: ${threatIntelResults.urlhaus.threat || 'N/A'}
` : ''}

Ta mission est d'analyser cet email en profendeur en utilisant TOUS les élèments ci-dessus et de fournir UNIQUEMENT un objet JSON avec cette structure exacte:
{
  "isPhishing": true/false,
  "confidence": 0-100,
  "risks": ["risque1", "risque2"],
  "explanation": "explication détaillée avec la meme langue que l'email",
  "recommendations": ["conseil1", "conseil2"]
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
            content: 'Tu es un expert en cybersécurité. Réponds toujours en JSON valide sans markdown.'
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
  console.log(`🚀 Serveur proxy démarré sur le port ${PORT}`);
  console.log(`📡 Frontend autorisé: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
  console.log(`🔑 Groq API Key configurée: ${process.env.GROQ_API_KEY ? '✓' : '✗'}`);
  
  // Charger les données de threat intelligence au démarrage
  try {
    console.log('📦 Chargement des données de threat intelligence...');
    threatIntelCache = await getThreatIntelData();
    console.log('✓ Threat intel chargé avec succès');
  } catch (error) {
    console.error('⚠ Erreur lors du chargement de threat intel:', error.message);
  }
});

module.exports = app;