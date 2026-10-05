/**
 * VIGILANTE Standardized STIX 2.1 / TAXII & MISP Threat Feed Pipeline
 * Native ingestion, transformation, validation, and export of STIX 2.1 JSON bundles,
 * bidirectional MISP 2.4 event conversion, TAXII 2.1 feed sync, and IOC deduplication.
 */

import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';

/**
 * Generate a deterministic or random STIX 2.1 UUID
 */
export function generateStixId(type, seed = null) {
  const uuid = seed 
    ? crypto.createHash('sha256').update(seed).digest('hex').substring(0, 32).replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5')
    : crypto.randomUUID();
  return `${type}--${uuid}`;
}

/**
 * Parse and validate a STIX 2.1 JSON Bundle
 * @param {string|Object} bundleData
 * @returns {Object} Structured STIX assessment
 */
export function parseStixBundle(bundleData) {
  if (!bundleData) throw new Error('Empty STIX bundle data');

  const bundle = typeof bundleData === 'string' ? JSON.parse(bundleData) : bundleData;

  if (bundle.type !== 'bundle') {
    throw new Error(`Invalid STIX object: expected type 'bundle', got '${bundle.type}'`);
  }

  const objects = Array.isArray(bundle.objects) ? bundle.objects : [];
  const objectsByType = {};
  const indicators = [];
  const relationships = [];

  for (const obj of objects) {
    const type = obj.type || 'unknown';
    if (!objectsByType[type]) objectsByType[type] = [];
    objectsByType[type].push(obj);

    if (type === 'indicator') {
      const extractedIoc = extractIocFromPattern(obj.pattern);
      indicators.push({
        id: obj.id,
        name: obj.name,
        pattern: obj.pattern,
        patternType: obj.pattern_type || 'stix',
        validFrom: obj.valid_from,
        confidence: obj.confidence || 75,
        iocType: extractedIoc.type,
        iocValue: extractedIoc.value
      });
    } else if (type === 'relationship') {
      relationships.push({
        id: obj.id,
        relationshipType: obj.relationship_type,
        sourceRef: obj.source_ref,
        targetRef: obj.target_ref
      });
    }
  }

  return {
    bundleId: bundle.id || generateStixId('bundle'),
    specVersion: bundle.spec_version || '2.1',
    totalObjects: objects.length,
    objectsByType,
    indicators,
    relationships,
    timestamp: new Date().toISOString()
  };
}

/**
 * Helper to extract raw IOC value and type from standard STIX pattern string
 */
function extractIocFromPattern(pattern = '') {
  if (!pattern) return { type: 'unknown', value: null };

  const ipv4Match = pattern.match(/ipv4-addr:value\s*=\s*'([^']+)'/i);
  if (ipv4Match) return { type: 'ipv4', value: ipv4Match[1] };

  const ipv6Match = pattern.match(/ipv6-addr:value\s*=\s*'([^']+)'/i);
  if (ipv6Match) return { type: 'ipv6', value: ipv6Match[1] };

  const domainMatch = pattern.match(/domain-name:value\s*=\s*'([^']+)'/i);
  if (domainMatch) return { type: 'domain', value: domainMatch[1] };

  const hashMatch = pattern.match(/file:hashes\.'SHA-256'\s*=\s*'([^']+)'/i);
  if (hashMatch) return { type: 'sha256', value: hashMatch[1] };

  const urlMatch = pattern.match(/url:value\s*=\s*'([^']+)'/i);
  if (urlMatch) return { type: 'url', value: urlMatch[1] };

  return { type: 'custom', value: pattern };
}

/**
 * Convert MISP 2.4 Event JSON into a valid STIX 2.1 Bundle
 * @param {Object} mispEvent
 * @returns {Object} STIX 2.1 Bundle
 */
export function convertMispToStix(mispEvent = {}) {
  const event = mispEvent.Event || mispEvent;
  const eventUuid = event.uuid || crypto.randomUUID();
  const eventInfo = event.info || 'MISP Threat Event';
  const timestamp = event.timestamp ? new Date(Number(event.timestamp) * 1000).toISOString() : new Date().toISOString();

  const stixObjects = [];

  // 1. Create Report / Threat-Actor or Attack-Pattern if tags exist
  const reportId = generateStixId('report', eventUuid);
  const objectRefs = [];

  // 2. Map MISP Attributes to STIX Indicators
  const attributes = Array.isArray(event.Attribute) ? event.Attribute : [];

  for (const attr of attributes) {
    const attrType = (attr.type || '').toLowerCase();
    const val = attr.value;
    let stixPattern = null;
    let patternType = 'stix';

    if (attrType === 'ip-dst' || attrType === 'ip-src' || attrType === 'ip') {
      stixPattern = `[ipv4-addr:value = '${val}']`;
    } else if (attrType === 'domain' || attrType === 'hostname') {
      stixPattern = `[domain-name:value = '${val}']`;
    } else if (attrType === 'sha256') {
      stixPattern = `[file:hashes.'SHA-256' = '${val}']`;
    } else if (attrType === 'url') {
      stixPattern = `[url:value = '${val}']`;
    } else if (attrType === 'yara') {
      stixPattern = val;
      patternType = 'yara';
    }

    if (stixPattern) {
      const indicatorId = generateStixId('indicator', `${eventUuid}-${val}`);
      const indicatorObj = {
        type: 'indicator',
        spec_version: '2.1',
        id: indicatorId,
        created: timestamp,
        modified: timestamp,
        name: `${attrType.toUpperCase()} Indicator: ${val}`,
        description: attr.comment || eventInfo,
        pattern: stixPattern,
        pattern_type: patternType,
        valid_from: timestamp,
        confidence: attr.to_ids ? 85 : 50
      };

      stixObjects.push(indicatorObj);
      objectRefs.push(indicatorId);
    }
  }

  // 3. Create enclosing Report object
  const reportObj = {
    type: 'report',
    spec_version: '2.1',
    id: reportId,
    created: timestamp,
    modified: timestamp,
    name: eventInfo,
    description: `Imported from MISP Event ${eventUuid}`,
    published: timestamp,
    object_refs: objectRefs
  };
  stixObjects.unshift(reportObj);

  return {
    type: 'bundle',
    id: generateStixId('bundle', eventUuid),
    objects: stixObjects
  };
}

/**
 * Convert a STIX 2.1 Bundle back to standard MISP 2.4 Event structure
 * @param {Object} stixBundle
 * @returns {Object} MISP 2.4 Event object
 */
export function convertStixToMisp(stixBundle = {}) {
  const parsed = parseStixBundle(stixBundle);
  const attributes = [];

  for (const ind of parsed.indicators) {
    let mispType = 'other';
    if (ind.iocType === 'ipv4') mispType = 'ip-dst';
    else if (ind.iocType === 'domain') mispType = 'domain';
    else if (ind.iocType === 'sha256') mispType = 'sha256';
    else if (ind.iocType === 'url') mispType = 'url';
    else if (ind.patternType === 'yara') mispType = 'yara';

    attributes.push({
      uuid: ind.id.replace(/^indicator--/, ''),
      type: mispType,
      value: ind.iocValue || ind.pattern,
      to_ids: ind.confidence >= 70,
      comment: ind.name
    });
  }

  return {
    Event: {
      uuid: parsed.bundleId.replace(/^bundle--/, ''),
      info: `Exported from STIX Bundle ${parsed.bundleId}`,
      date: new Date().toISOString().split('T')[0],
      threat_level_id: '2',
      Attribute: attributes
    }
  };
}

/**
 * Merge multiple threat feeds, deduplicating IOCs and calculating unified confidence
 * @param {Array<Object>} feedList List of parsed STIX bundles
 * @returns {Array<Object>} Merged deduplicated IOC list
 */
export function mergeThreatFeeds(feedList = []) {
  const iocMap = new Map();

  for (const feed of feedList) {
    const indicators = feed.indicators || [];
    for (const ind of indicators) {
      const key = `${ind.iocType}:${ind.iocValue}`;
      if (!iocMap.has(key)) {
        iocMap.set(key, {
          iocType: ind.iocType,
          iocValue: ind.iocValue,
          patterns: [ind.pattern],
          sourceFeedCount: 1,
          maxConfidence: ind.confidence || 70,
          firstSeen: ind.validFrom || new Date().toISOString(),
          lastSeen: ind.validFrom || new Date().toISOString()
        });
      } else {
        const existing = iocMap.get(key);
        existing.sourceFeedCount += 1;
        existing.maxConfidence = Math.max(existing.maxConfidence, ind.confidence || 70);
        if (!existing.patterns.includes(ind.pattern)) existing.patterns.push(ind.pattern);
      }
    }
  }

  return Array.from(iocMap.values());
}

/**
 * Filter indicators by type, minimum confidence, or query string
 * @param {Array<Object>} indicators
 * @param {Object} [criteria={}]
 * @returns {Array<Object>}
 */
export function filterIndicators(indicators = [], criteria = {}) {
  return indicators.filter(ind => {
    if (criteria.type && ind.iocType !== criteria.type) return false;
    if (criteria.minConfidence && (ind.confidence || 0) < criteria.minConfidence) return false;
    if (criteria.query) {
      const q = criteria.query.toLowerCase();
      const valMatch = ind.iocValue && ind.iocValue.toLowerCase().includes(q);
      const nameMatch = ind.name && ind.name.toLowerCase().includes(q);
      if (!valMatch && !nameMatch) return false;
    }
    return true;
  });
}
