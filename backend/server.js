require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3001;

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
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
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

Fournis UNIQUEMENT un objet JSON avec cette structure exacte:
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

app.listen(PORT, () => {
  console.log(`🚀 Serveur proxy démarré sur le port ${PORT}`);
  console.log(`📡 Frontend autorisé: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
  console.log(`🔑 Groq API Key configurée: ${process.env.GROQ_API_KEY ? '✓' : '✗'}`);
});

module.exports = app;