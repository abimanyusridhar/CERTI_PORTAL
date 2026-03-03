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

    // Team identifiers  (only differ here — one has a space, one doesn't)
    cstTeamSuffix:  'Cyber Security Team',          // → "<company> Cyber Security Team"
    vaptTeamSuffix: 'Cybersecurity Team',           // → "<company> Cybersecurity Team"
    division:       'Cyber Security And Compliance Division',

    // Emails
    cstEmail:  'trainingawareness@synergyship.com',
    vaptEmail: 'vapt@synergyship.com',

    // Routes  (change once — all href / fetch paths update)
    routeCST:  '/CST',
    routeVPT:  '/VPT',

    // Certificate ID prefixes
    cstPrefix:  'CST',                          // → "CST-{IMO}-{MM}-{YY}"
    vaptPrefix: 'VAP',                          // → "VAP-{IMO}-{MMYY}"

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
  var cisoOrg = A.cisoRole + ', ' + A.company;

  /* ═══════════════════════════════════════════════════════════════════════
   * §3  FULL CONFIGURATION OBJECT  —  consumes only §1 atoms and §2 vars
   * ═══════════════════════════════════════════════════════════════════════ */
  var cfg = {

    // ── BRAND & COMPANY ──────────────────────────────────────────────────
    brand: {
      name:        A.company,
      companyFull: A.company,
      cstTeam:     cstTeam,
      vaptTeam:    vaptTeam,
      division:    A.company + ' ' + A.division,
      adminRole:   'Full Access \u00b7 ' + A.company,
    },

    // ── CONTACT EMAILS ───────────────────────────────────────────────────
    contact: {
      cstEmail:  A.cstEmail,
      vaptEmail: A.vaptEmail,
    },

    // ── ROUTES ───────────────────────────────────────────────────────────
    routes: {
      cst:      A.routeCST,
      vpt:      A.routeVPT,
      cstAdmin: A.routeCST + '/admin',
      vptAdmin: A.routeVPT + '/admin',
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
      cstSidebarName: A.companyShort + ' CST',
      vptSidebarName: A.companyShort + ' VPT',
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
      searchPlaceholder: 'e.g. CST-9902873-02-26',
      searchHint:        'Format: CST-&lt;IMO&gt;-&lt;MM&gt;-&lt;YY&gt;'
                           + ' &nbsp;&middot;&nbsp; Case insensitive'
                           + ' &nbsp;&middot;&nbsp; Example: CST-99028XX-0X-26',
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
      verifierTitle:   cisoDisplay,
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

    // ── EMAIL TEMPLATES ──────────────────────────────────────────────────
    // Functions so they interpolate live cert data at call-time.
    emailTemplates: {
      /**
       * CST training email body
       * @param {object} c        - certificate object
       * @param {string} verifyUrl - public verification URL
       */
      cst: function (c, verifyUrl) {
        var d = c.complianceDate
          ? new Date(c.complianceDate).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
          : '\u2014';
        return 'Dear Sir / Madam,\n\n'
          + 'Please find below the Cyber Security Threat Awareness Training certificate details for your records.\n\n'
          + 'Vessel            : ' + (c.recipientName     || '\u2014') + '\n'
          + 'Vessel IMO        : ' + (c.vesselIMO         || '\u2014') + '\n'
          + 'Chief Engineer    : ' + (c.chiefEngineer     || '\u2014') + '\n'
          + 'Certificate No.   : ' + c.id                              + '\n'
          + 'Compliance Date   : ' + d                                 + '\n'
          + 'Compliance Quarter: ' + (c.complianceQuarter || '\u2014') + '\n'
          + 'Training Mode     : ' + (c.trainingMode      || '\u2014') + '\n'
          + 'Valid For         : ' + (c.validFor          || '\u2014') + '\n\n'
          + 'Verify online at:\n' + verifyUrl + '\n\n'
          + 'This training was organized by the ' + cstTeam + ' and conducted\n'
          + 'under supervision of ISO Lead Auditor and Security trainers.\n\n'
          + 'Regards,\n'
          + cstTeam + '\n'
          + A.cstEmail;
      },

      /**
       * VAPT email body
       * @param {object} c       - certificate object
       * @param {string} certUrl - public verification URL
       */
      vapt: function (c, certUrl) {
        return 'Subject: Your VAPT Certificate \u2014 ' + c.id + ' \u2014 ' + A.companyShort + ' Group\n\n'
          + 'Dear ' + (c.recipientName || c.vesselName) + ',\n\n'
          + 'Please find below your Vulnerability Assessment & Penetration Testing (VAPT)\n'
          + 'certificate details from ' + A.company + ' Cyber Security Division.\n\n'
          + 'Certificate ID   : ' + c.id                                          + '\n'
          + 'Vessel           : ' + c.vesselName                                  + '\n'
          + 'IMO Number       : ' + c.vesselIMO                                   + '\n'
          + 'Assessment Date  : ' + c.assessmentDate                              + '\n'
          + 'Valid Until      : ' + c.validUntil                                  + '\n'
          + 'Status           : ' + c.status                                      + '\n'
          + 'Frameworks       : ' + (c.frameworks || A.frameworks)                + '\n\n'
          + 'Verification Link: ' + certUrl + '\n\n'
          + 'For questions or re-assessment, contact us at ' + A.vaptEmail + '.\n\n'
          + (c.verifiedBy    || A.cisoName)  + '\n'
          + (c.verifierTitle || cisoDisplay) + '\n'
          + A.company + ' \u00b7 Cyber Security Division';
      },
    },

  };

  // ── UMD export ────────────────────────────────────────────────────────────
  // Node.js  →  module.exports  (server: require('./config/app.config'))
  // Browser  →  window.APP_CONFIG  (HTML: <script src="/config.js"></script>)
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = cfg;
  } else {
    root.APP_CONFIG = cfg;
  }

}(typeof window !== 'undefined' ? window : (typeof global !== 'undefined' ? global : this)));