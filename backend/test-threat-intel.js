#!/usr/bin/env node

/**
 * Script de test pour vérifier que les données de threat intelligence 
 * sont correctement chargées depuis le backend
 */

const fetch = require('node-fetch');

const BACKEND_URL = 'http://localhost:3001';

async function testThreatIntel() {
  console.log('\n📋 Test du serveur de Threat Intelligence\n');
  console.log('Vérification que le backend est en cours d\'exécution...\n');

  try {
    // Test 1: Health check
    console.log('1️⃣  Vérification de la santé du serveur...');
    const healthResponse = await fetch(`${BACKEND_URL}/api/health`);
    if (healthResponse.ok) {
      const healthData = await healthResponse.json();
      console.log('   ✓ Serveur réactif:', healthData.status);
    } else {
      throw new Error(`Health check failed: ${healthResponse.status}`);
    }

    // Test 2: Threat Intel Loading
    console.log('\n2️⃣  Chargement des données de threat intelligence...');
    const threatResponse = await fetch(`${BACKEND_URL}/api/threat-intel`);
    if (threatResponse.ok) {
      const threatData = await threatResponse.json();
      console.log('   ✓ Données chargées avec succès');
      console.log(`   📊 ${threatData.data.stats.totalMaliciousDomains} domaines malveillants détectés`);
      console.log(`   🐟 ${threatData.data.stats.openphishUrls} URLs OpenPhish chargées`);
      console.log(`   🌐 ${threatData.data.stats.urlhausDomains} domaines URLhaus chargés`);
      console.log(`   💾 Cache valide: ${threatData.data.cacheValid}`);
      console.log(`   ⏰ Dernière mise à jour: ${threatData.data.lastUpdated}`);
    } else {
      throw new Error(`Threat intel failed: ${threatResponse.status}`);
    }

    // Test 3: Domain Check
    console.log('\n3️⃣  Vérification d\'un domaine malveillant (test paypa1.com)...');
    const domainResponse = await fetch(`${BACKEND_URL}/api/threat-intel/check-domain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: 'paypa1.com' })
    });

    if (domainResponse.ok) {
      const domainData = await domainResponse.json();
      console.log(`   ✓ Domaine trouvé: ${domainData.domain}`);
      console.log(`   ⚠️  Malveillant: ${domainData.isMalicious ? 'OUI (détecté)' : 'NON'}`);
    } else {
      throw new Error(`Domain check failed: ${domainResponse.status}`);
    }

    console.log('\n✅ Tous les tests sont passés avec succès!\n');
    console.log('💡 Le backend est prêt à servir l\'application frontend.\n');

  } catch (error) {
    console.error('\n❌ Erreur lors du test:', error.message);
    console.error('\n💡 Assurez-vous que le backend est démarré avec: npm start (dans ./backend)\n');
    process.exit(1);
  }
}

testThreatIntel();
