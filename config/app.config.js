/**
 * ╔══════════════════════════════════════════════════════════════════════╗
 * ║              SINGLE CENTRALIZED CONFIGURATION                        ║
 * ║              config/app.config.js                                    ║
 * ║                                                                      ║
 * ║  ONE file · zero duplication · works in BOTH environments:          ║
 * ║                                                                      ║
 * ║  ▸ Server  (Node.js)  →  const CFG = require('./config/app.config') ║
 * ║  ▸ Browser (HTML)     →  <script src="/config.js"></script>         ║
 * ║                           then access: window.APP_CONFIG.brand.name ║
 * ║                                                                      ║
 * ║  ────────────────────────────────────────────────────────────────── ║
 * ║  HOW TO REBRAND / REDEPLOY                                           ║
 * ║  Edit only the BASE ATOMS block below (section 1).                  ║
 * ║  Every title, label, banner, email template, and footer across       ║
 * ║  all pages derives from those atoms — nothing else needs touching.  ║
 * ╚══════════════════════════════════════════════════════════════════════╝
 */

/* global module, window */
(function (root) {
  'use strict';

  /* ═══════════════════════════════════════════════════════════════════════
   * §1  BASE ATOMS  —  THE ONLY VALUES YOU EVER NEED TO EDIT
   *
   *     Every string in §2 onwards is derived from these.
   *     Change here → everything updates automatically.
   * ═══════════════════════════════════════════════════════════════════════ */
  var A = {
    // Company
    company:       'Synergy Marine Group',          // canonical company name
    companyShort:  'Synergy',                       // prefix used in short labels

    // People
    cisoName:      'Gaurav Singh',
    cisoRole:      'CISO',                          // short role token
    cisoFullTitle: 'Chief Information Security Officer',

    // Team identifiers
    cstTeamSuffix:  'Cyber Security Team',          // → "<company> Cyber Security Team"
    vaptTeamSuffix: 'Cybersecurity Team',           // → "<company> Cybersecurity Team"
    division:       'Cyber Security And Compliance Division',

    // Emails
    cstEmail:  'trainingawareness@synergyship.com',
    vaptEmail: 'vapt@synergyship.com',

    // Routes  (change once — all href / fetch paths update)
    routeCST:  '/CST',
    routeVPT:  '/VAPT',

    // Certificate ID prefixes
    cstPrefix:  'CST',
    vaptPrefix: 'VAP',

    // Training programme label
    trainingTitle: 'Cyber Security Threat Intelligence Awareness Training',

    // Assessment frameworks (VAPT)
    frameworks: 'Cybersecurity Framework / OWASP / IMO Framework / ISO 27001:2013',

    // VAPT scope line-items (comma-separated)
    scopeItems: [
      'Access Control (USB/Data/Login/Domain/Email/Assets)',
      'IT/OT Risk analysis',
      'Vessel Cyber security awareness',
      'Software Version Control (IT/OT)',
      'Backups & Disaster Recovery',
      'IT Drills & Internal Audits',
    ].join(','),
  };

  /* ═══════════════════════════════════════════════════════════════════════
   * §2  DERIVED IDENTIFIERS  —  built once from §1 atoms
   * ═══════════════════════════════════════════════════════════════════════ */

  /** "Synergy Marine Group Cyber Security Team" */
  var cstTeam = A.company + ' ' + A.cstTeamSuffix;

  /** "Synergy Marine Group Cybersecurity Team" */
  var vaptTeam = A.company + ' ' + A.vaptTeamSuffix;

  /** "Gaurav Singh, CISO" */
  var cisoShort = A.cisoName + ', ' + A.cisoRole;

  /** "Gaurav Singh, CISO - Chief Information Security Officer, Synergy Marine Group" */
  var cisoFull = A.cisoName + ', ' + A.cisoRole + ' - ' + A.cisoFullTitle + ', ' + A.company;

  /** "CISO — Synergy Group"  (used in VAPT verifier title display) */
  var cisoDisplay = A.cisoRole + ' \u2014 ' + A.companyShort + ' Group';

  /** "CISO, Synergy Marine Group"  (used in CST verified-by fallback) */
  var cisoOrg = A.cisoRole + ', ' + A.company;   // eslint-disable-line no-unused-vars

  /* ═══════════════════════════════════════════════════════════════════════
   * §3  FULL CONFIGURATION OBJECT  —  consumes only §1 atoms and §2 vars
   * ═══════════════════════════════════════════════════════════════════════ */
  var cfg = {

    // ── CONFIG VERSION ───────────────────────────────────────────────────
    // Increment when making structural changes so pages can detect stale
    // cached configs.  Format: "<major>.<minor>.<patch>"
    version: '2.0.0',  // Added: compliance, session, resilience, maintenance, health, support sections

    // ── STORAGE KEYS ─────────────────────────────────────────────────────
    // Centralised so all pages share the same key — never diverge silently.
    storageKeys: {
      theme: 'smg-theme',
    },

    // ── BRAND & COMPANY ──────────────────────────────────────────────────
    brand: {
      name:         A.company,
      companyFull:  A.company,
      companyShort: A.companyShort,   // FIX: exposed so CFG.brand.companyShort / APP_CONFIG.brand.companyShort resolve correctly
      cstTeam:      cstTeam,
      vaptTeam:     vaptTeam,
      division:     A.company + ' ' + A.division,
      adminRole:    'Full Access \u00b7 ' + A.company,
    },

    // ── CONTACT EMAILS ───────────────────────────────────────────────────
    contact: {
      cstEmail:  A.cstEmail,
      vaptEmail: A.vaptEmail,
    },

    // ── ROUTES ───────────────────────────────────────────────────────────
    // NOTE: cst/vpt (the public verify routes) are load-bearing for every
    // certificate email already sent — the verify link is built from these
    // at send-time and can never change shape for a cert already issued.
    // The admin-only routes below have no such constraint and can be
    // renamed freely; old paths 301-redirect for continuity (see server/index.js).
    routes: {
      cst:      A.routeCST,
      vpt:      A.routeVPT,
      cstAdmin: '/console/cst',
      vptAdmin: '/console/vapt',
      portal:   '/console/portal',
    },

    // ── CERTIFICATE ID FORMATS ───────────────────────────────────────────
    certFormats: {
      cstPrefix:  A.cstPrefix,   // "CST" → CST-{IMO}-{MM}-{YY}
      vaptPrefix: A.vaptPrefix,  // "VAP" → VAP-{IMO}-{MMYY}
    },

    // ── PAGE TITLES ──────────────────────────────────────────────────────
    titles: {
      cstPortal:  A.company + ' \u2014 Certificate Verification',
      vaptPortal: A.companyShort + ' Group \u2014 VAPT Assessment Verification',
      cstAdmin:   A.companyShort + ' Admin \u2014 Certificate Control Panel',
      vaptAdmin:  A.companyShort + ' Admin \u2014 VAPT Certificate Control Panel',
    },

    // ── NAV & SIDEBAR LABELS ─────────────────────────────────────────────
    nav: {
      cstBrandSub:    'Certificate Registry',
      vaptBrandSub:   'VAPT Assessment Registry',
      cstTabLabel:    'CST Training',
      vptTabLabel:    'VAPT Assessment',
      // FIX: was 'Synergy VPT' — corrected to 'Synergy VAPT' for consistency
      cstSidebarName: A.companyShort + ' CST',
      vptSidebarName: A.companyShort + ' VAPT',
      cstLoginSub:    A.companyShort + ' Certificate Control Panel',
      vaptLoginSub:   'VAPT Certificate Control Panel',
    },

    // ── CST CERTIFICATE DEFAULTS ─────────────────────────────────────────
    cst: {
      trainingTitle:     A.trainingTitle,
      organizer:         cstTeam,
      verifiedBy:        cisoFull,
      notes:             'Training conducted under supervision of ISO Lead Auditor and Security trainers',
      issuerEmail:       A.cstEmail,
      previewSigName:    cisoShort,
      previewOrgName:    A.company,
      csvFormatHint:     'Accepts .csv files matching the ' + A.companyShort + ' CSV format',
      heroSub:           'Enter a Cyber Security Training (CST) certificate number from any '
                           + A.companyShort + ' training document. Real-time verification for '
                           + 'maritime compliance officers, port authorities, and PSC inspectors.',
      searchPlaceholder: 'Enter CST certificate number',
      searchHint:        'Enter your CST certificate number as provided in your training document',
      readOnlyNote:      'This record is read-only \u00b7 verified directly from the '
                           + A.companyShort + ' registry',
      pendingNote:       'Contact the ' + cstTeam + ' for status updates.',
      registryBanner:    A.companyShort + ' Cyber Security Registry'
                           + ' &nbsp;&middot;&nbsp; ISO Lead Auditor Supervision',
      footerCredit:      A.company + ' &middot; Cyber Security Certificate Registry',
    },

    // ── VAPT CERTIFICATE DEFAULTS ────────────────────────────────────────
    vapt: {
      verifiedBy:      A.cisoName,
      verifierTitle:   cisoDisplay,                      // "CISO — Synergy Group"
      certPlaceholder: 'Enter VAPT certificate number',
      searchHint:      'Enter your VAPT certificate number as provided in your assessment report',
      assessingOrg:    vaptTeam,
      frameworks:      A.frameworks,
      scopeItems:      A.scopeItems,
      issuerEmail:     A.vaptEmail,
      previewSigName:  cisoShort,
      previewOrgName:  A.company,
      previewTeamName: vaptTeam,
      cisoDisplay:     cisoDisplay,
      heroSub:         'Enter a Vulnerability &amp; Penetration Testing (VAPT) certificate number '
                         + 'to get real-time verification of vessel cybersecurity assessment status '
                         + 'for maritime compliance and vetting inspectors.',
      readOnlyNote:    'This record is read-only \u00b7 verified directly from the '
                         + A.companyShort + ' VAPT registry',
      registryBanner:  A.companyShort + ' VAPT Certificate Registry'
                         + ' &nbsp;&middot;&nbsp; ISO Lead Auditor Supervision',
      footerCredit:    A.company + ' &middot; VAPT Certificate Registry',
    },

    // ── COMPLIANCE & LEGAL ───────────────────────────────────────────────
    // Maritime regulatory framework alignment and data governance declarations.
    compliance: {
      // Applicable regulatory / standards frameworks
      standards:          'IMO MSC-FAL.1/Circ.3 · ISO 27001:2022 · ISO 9001:2015 · NIST CSF · OWASP · MLC 2006',
      // Data classification for certificates issued via this portal
      dataClassification: 'RESTRICTED — Maritime Personnel & Vessel Security Records',
      // Data retention period (displayed in legal notices)
      dataRetentionYears: 5,
      // GDPR / privacy contact
      privacyContact:     'dpo@synergyship.com',
      // Legal jurisdiction
      jurisdiction:       'Republic of Singapore (MPA-registered flag state authority)',
      // Applicable law
      governingLaw:       'Singapore Merchant Shipping Act · ISM Code · ISPS Code',
      // Certificate disclaimer shown on public verification pages
      publicDisclaimer:   'Certificate records are issued and maintained by Synergy Marine Group. '
                          + 'Verification results are provided for information only and do not constitute '
                          + 'a legal opinion. Fraudulent use or alteration of certificates may be subject '
                          + 'to criminal prosecution under applicable maritime law.',
      // Admin data notice
      adminDataNotice:    'All administrative actions on this panel are logged and audited. '
                          + 'Unauthorised access is prohibited. By continuing you acknowledge '
                          + 'your activity may be monitored.',
      // Cookie / tracking notice (public portals)
      cookieNotice:       'This portal does not use marketing cookies. '
                          + 'Essential session data is stored only for verification functionality.',
      // VAPT-specific notice
      vaptDisclaimer:     'VAPT assessment records contain sensitive cybersecurity findings. '
                          + 'Access is restricted to authorised maritime compliance personnel.',
    },

    // ── SESSION & TIMEOUT ────────────────────────────────────────────────
    session: {
      // Admin session max duration (ms) — must match JWT expiry in server
      maxDurationMs:      8 * 60 * 60 * 1000,  // 8 hours
      // Show session-expiry warning this many ms before logout
      warningBeforeMs:    5 * 60 * 1000,        // 5 minutes
      // Idle timeout — auto-logout after this many ms without activity
      idleTimeoutMs:      30 * 60 * 1000,       // 30 minutes
      // Idle warning this many ms before idle logout
      idleWarningBeforeMs: 2 * 60 * 1000,       // 2 minutes
      // Public portal: cache last-verified cert ID for this long (ms)
      publicCacheMs:      10 * 60 * 1000,       // 10 minutes
    },

    // ── AVAILABILITY & RESILIENCE ────────────────────────────────────────
    resilience: {
      // Public verify API: number of automatic retries on transient failure
      apiRetryCount:      3,
      // Initial retry delay (ms) — doubles with each attempt (exponential backoff)
      apiRetryDelayMs:    800,
      // Timeout for a single API request (ms)
      apiTimeoutMs:       12000,
      // Health-check poll interval when offline banner is shown (ms)
      offlinePollMs:      8000,
    },

    // ── MAINTENANCE MODE ─────────────────────────────────────────────────
    // Set `enabled: true` to display a maintenance banner without taking the app offline.
    // For full downtime: also set the MAINTENANCE_MODE env variable server-side.
    maintenance: {
      enabled:            false,
      message:            'Scheduled maintenance in progress. The verification portal '
                          + 'may be intermittently unavailable. Expected resolution: ',
      eta:                '',   // e.g. "2026-03-22 04:00 UTC" — leave blank to omit
      contactEmail:       'trainingawareness@synergyship.com',
    },

    // ── HEALTH & OBSERVABILITY ───────────────────────────────────────────
    health: {
      // Path served by the Node server for load-balancer / uptime checks
      endpoint:           '/health',
      // Public status page (external, optional)
      statusPage:         '',
    },

    // ── EMAIL TEMPLATES ──────────────────────────────────────────────────
    // Functions so they interpolate live cert data at call-time.
    emailTemplates: {
      /**
       * CST training email body.
       * @param {object} c        - certificate object
       * @param {string} verifyUrl - public verification URL
       * @returns {string}
       */
      cst: function (c, verifyUrl) {
        var d = c.complianceDate
          ? new Date(c.complianceDate).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
          : '\u2014';
        var exp = c.validUntil
          ? new Date(c.validUntil).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
          : '\u2014';
        return 'Dear ' + (c.recipientName || c.vesselName || 'Sir / Madam') + ',\n\n'
          + 'Congratulations on the successful completion of the Cyber Security Threat Intelligence Awareness Training!\n\n'
          + 'We are pleased to confirm that your certificate has been issued and is now available for verification. '
          + 'Please find the certificate details below for your records.\n\n'
          + 'Vessel            : ' + (c.recipientName     || '\u2014') + '\n'
          + 'Vessel IMO        : ' + (c.vesselIMO         || '\u2014') + '\n'
          + 'Chief Engineer    : ' + (c.chiefEngineer     || '\u2014') + '\n'
          + 'Certificate No.   : ' + c.id                              + '\n'
          + 'Compliance Date   : ' + d                                 + '\n'
          + 'Compliance Quarter: ' + (c.complianceQuarter || '\u2014') + '\n'
          + 'Training Mode     : ' + (c.trainingMode      || '\u2014') + '\n'
          + 'Valid For         : ' + (c.validFor          || '90 Days') + '\n'
          + 'Valid Until       : ' + exp                               + '\n\n'
          + 'Your certificate image is attached to this email for your records.\n\n'
          + 'To verify the authenticity of this certificate at any time, use the link below\n'
          + 'or enter Certificate No. ' + c.id + ' at the Synergy Cyber Security Certificate Portal:\n\n'
          + verifyUrl + '\n\n'
          + 'This training was organized by the ' + cstTeam + ' and conducted\n'
          + 'under the supervision of ISO Lead Auditor and Cyber Security trainers.\n\n'
          + 'We commend the vessel crew for their commitment to maritime cyber security and look\n'
          + 'forward to your continued participation in future training programmes.\n\n'
          + 'Warm regards,\n'
          + cstTeam + '\n'
          + A.cstEmail;
      },

      /**
       * VAPT email body.
       * @param {object} c       - certificate object
       * @param {string} certUrl - public verification URL
       * @returns {string}
       */
      vapt: function (c, certUrl) {
        var ad = c.assessmentDate
          ? new Date(c.assessmentDate).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
          : '\u2014';
        var exp = c.validUntil
          ? new Date(c.validUntil).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
          : '\u2014';
        return 'Subject: Your VAPT Certificate \u2014 ' + c.id + ' \u2014 ' + A.companyShort + ' Group\n\n'
          + 'Dear ' + (c.recipientName || c.vesselName) + ',\n\n'
          + 'Congratulations on the successful completion of the Vulnerability Assessment & Penetration Testing (VAPT)!\n\n'
          + 'We are pleased to confirm that your VAPT certificate has been issued by '
          + A.company + ' Cyber Security Division. Please find the certificate details below.\n\n'
          + 'Certificate ID   : ' + c.id                                          + '\n'
          + 'Vessel           : ' + (c.vesselName  || '\u2014')                        + '\n'
          + 'IMO Number       : ' + (c.vesselIMO   || '\u2014')                        + '\n'
          + 'Assessment Date  : ' + ad                                             + '\n'
          + 'Valid Until      : ' + exp                                            + '\n'
          + 'Status           : ' + (c.status || 'VALID')                         + '\n'
          + 'Frameworks       : ' + (c.frameworks || A.frameworks)                + '\n\n'
          + 'Your certificate image is attached to this email for your records.\n\n'
          + 'To verify the authenticity of this certificate at any time, use the link below\n'
          + 'or enter Certificate No. ' + c.id + ' at the VAPT verification portal:\n\n'
          + certUrl + '\n\n'
          + 'We appreciate your vessel\'s commitment to cyber resilience and look forward to\n'
          + 'supporting your continued compliance journey.\n\n'
          + 'For re-assessment enquiries, contact us at ' + A.vaptEmail + '.\n\n'
          + 'Warm regards,\n'
          + (c.verifiedBy    || A.cisoName)  + '\n'
          + (c.verifierTitle || cisoDisplay) + '\n'
          + A.company + ' \u00b7 Cyber Security Division';
      },
    },

  };

  /* ═══════════════════════════════════════════════════════════════════════
   * §4  BROWSER-SAFE VIEW  —  what actually gets shipped to /config.js
   *
   *     The full `cfg` above (personal CISO name/title + emailTemplates
   *     source) is for SERVER use only (email generation, defaulting a new
   *     certificate's `verifiedBy` field). None of that belongs in a static
   *     file any anonymous visitor can fetch without ever verifying a real
   *     certificate — doing so lets an attacker scrape the CISO's full name
   *     for spear-phishing without any interaction with the product.
   *
   *     `verifiedBy`/`previewSigName` fall back to a role-only string here;
   *     real issued certificates keep the actual signatory because that is
   *     populated server-side from `cfg.cst.verifiedBy` / `cfg.vapt.verifiedBy`
   *     at certificate-creation time, never from this browser copy.
   * ═══════════════════════════════════════════════════════════════════════ */
  cfg.buildBrowserConfig = function () {
    var roleWithCompany = A.cisoRole + ', ' + A.company; // "CISO, Synergy Marine Group" — no personal name
    var safe = {};
    for (var k in cfg) {
      if (k === 'buildBrowserConfig' || k === 'emailTemplates') continue;
      safe[k] = cfg[k];
    }
    safe.cst  = Object.assign({}, cfg.cst,  { verifiedBy: roleWithCompany, previewSigName: roleWithCompany });
    safe.vapt = Object.assign({}, cfg.vapt, { verifiedBy: A.cisoRole,      previewSigName: roleWithCompany });
    return safe;
  };

  // ── UMD export ────────────────────────────────────────────────────────────
  // Node.js  →  module.exports  (server: require('./config/app.config'))
  // Browser  →  window.APP_CONFIG  (HTML: <script src="/config.js" defer></script>)
  //             then access via: window.APP_CONFIG.brand.name
  //             or listen for:   document.addEventListener('appconfigready', fn)
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = cfg;
  } else {
    root.APP_CONFIG = cfg;
    // Dispatch a custom event so deferred consumers know config is ready
    if (typeof document !== 'undefined') {
      var evt = typeof CustomEvent === 'function'
        ? new CustomEvent('appconfigready', { detail: cfg })
        : (function () {
            var e = document.createEvent('Event');
            e.initEvent('appconfigready', true, true);
            e.detail = cfg;
            return e;
          }());
      document.dispatchEvent(evt);
    }
  }

}(typeof window !== 'undefined' ? window : (typeof global !== 'undefined' ? global : this)));