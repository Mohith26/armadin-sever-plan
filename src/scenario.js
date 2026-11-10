// Synthetic environment for the Sever Plan demo: a fictional logistics company
// ("Meridian Freight"), the kill-chain graph a hyperattack campaign validated,
// the compensating controls a defender could push, and 14 days of seeded
// telemetry (legitimate traffic plus the swarm's own recorded attack attempts).
// Everything downstream (replay, bounds, optimization) is computed from this.

export const SEED = 20261104;
export const DAYS = 14;
export const DAY0 = '2026-10-22';

export function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function poissonSample(rng, lambda) {
  if (lambda <= 0) return 0;
  if (lambda > 60) {
    // normal approximation for large means
    const u1 = Math.max(rng(), 1e-12), u2 = rng();
    const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    return Math.max(0, Math.round(lambda + Math.sqrt(lambda) * z));
  }
  const L = Math.exp(-lambda);
  let k = 0, p = 1;
  do { k++; p *= rng(); } while (p > L);
  return k - 1;
}

const pick = (rng, arr) => arr[Math.floor(rng() * arr.length)];

// ---------------------------------------------------------------------------
// Kill-chain graph
// ---------------------------------------------------------------------------
export const STEPS = {
  E1: { label: 'SSRF via callback_url', asset: 'quote-api', detail: 'Unauthenticated SSRF in the public quote API callback parameter', tactic: 'Initial access', icon: 'globe', src: 'waf.quote-api' },
  E2: { label: 'Exposed CLAUDE.md', asset: 'www', detail: 'Public CLAUDE.md on the marketing site lists internal hosts and a staging deploy token', tactic: 'Reconnaissance', icon: 'file-text', src: 'waf.www' },
  E3: { label: 'Legacy-auth password spray', asset: 'Entra ID', detail: 'Basic-auth IMAP/SMTP endpoints accept password guesses without MFA', tactic: 'Credential access', icon: 'user', src: 'entra.signin' },
  E4: { label: 'MFT admin console exposed', asset: 'mft-01', detail: 'Managed file transfer admin console reachable from the internet with a vendor default account', tactic: 'Initial access', icon: 'monitor', src: 'waf.mft' },
  E5: { label: 'VPN portal path traversal', asset: 'vpn-01', detail: 'Pre-auth path traversal in the VPN portal (public CVE, unpatched)', tactic: 'Initial access', icon: 'shield', src: 'waf.vpn' },
  P1: { label: 'IMDSv1 instance credentials', asset: 'quote-api EC2', detail: 'SSRF reads role credentials from the v1 metadata endpoint', tactic: 'Credential access', icon: 'key-round', src: 'imds.quote-api' },
  P2: { label: 'kube-apiserver from quote pods', asset: 'eks-prod', detail: 'Quote pods can reach the Kubernetes API server', tactic: 'Lateral movement', icon: 'network', src: 'k8s.audit' },
  P3: { label: 'Cluster-admin service account', asset: 'eks-prod', detail: 'quote-api service account token is bound to cluster-admin', tactic: 'Privilege escalation', icon: 'boxes', src: 'k8s.audit' },
  P4: { label: 'Staging token accepted in prod', asset: 'deploy API', detail: 'Prod deploy API accepts staging-scoped tokens', tactic: 'Privilege escalation', icon: 'key-round', src: 'apigw.deploy' },
  P5: { label: 'Shell from MFT service', asset: 'mft-01', detail: 'Admin console job runner spawns a shell as the MFT service', tactic: 'Execution', icon: 'terminal', src: 'edr.mft-01' },
  P6: { label: 'WebDAV auth coercion', asset: 'DC-01, DC-02', detail: 'Servers coerced to authenticate over WebDAV (WebClient)', tactic: 'Credential access', icon: 'radio-tower', src: 'net.webdav' },
  P7: { label: 'NTLM relay to AD CS', asset: 'ca-01 web enrollment', detail: 'Relayed machine auth enrolls a certificate (ESC8)', tactic: 'Privilege escalation', icon: 'file-badge', src: 'iis.certsrv' },
  P8: { label: 'Kerberoast svc-backup', asset: 'svc-backup', detail: 'RC4 service ticket for svc-backup cracked offline', tactic: 'Credential access', icon: 'ticket', src: 'dc.tgs' },
  P9: { label: 'SMB to backup tier', asset: 'bkp-01..04', detail: 'User VLAN hosts can reach backup servers over SMB', tactic: 'Lateral movement', icon: 'hard-drive', src: 'net.backup-smb' },
  P10: { label: 'LSASS read on jump host', asset: 'jmp-01..03', detail: 'Admin credentials recovered from jump host memory', tactic: 'Credential access', icon: 'cpu', src: 'edr.jump' },
  P11: { label: 'vCenter with reused creds', asset: 'vcsa-01', detail: 'vCenter accepts domain credentials without MFA', tactic: 'Lateral movement', icon: 'server', src: 'vcenter.auth' },
};

export const OBJECTIVES = {
  O1: { label: 'Customer database', kind: 'SENSITIVE DATA', detail: 'pg-prod: 2.1M shipper records' },
  O2: { label: 'Domain admin', kind: 'DOMAIN COMPROMISE', detail: 'meridian.local' },
  O3: { label: 'Backup servers', kind: 'BACKUP SERVERS', detail: 'bkp-01..04, ransomware precondition' },
  O4: { label: 'Hypervisor cluster', kind: 'HYPERVISOR', detail: 'vcsa-01, 212 VMs' },
  O5: { label: 'Cloud data lake', kind: 'SENSITIVE DATA', detail: 's3://mf-lake-prod' },
};

export const EDGES = [
  ['E1', 'P1'], ['E1', 'P2'], ['P1', 'O5'], ['P1', 'P3'], ['P2', 'P3'], ['P3', 'O1'], ['P3', 'O5'],
  ['E2', 'P4'], ['P4', 'O1'],
  ['E3', 'P6'], ['E3', 'P8'], ['P6', 'P7'], ['P7', 'O2'], ['P8', 'P9'], ['P9', 'O3'], ['P8', 'P11'], ['P11', 'O4'],
  ['E4', 'P5'], ['P5', 'P10'], ['P5', 'P6'], ['P10', 'O2'], ['P10', 'P11'],
  ['E5', 'P10'], ['E5', 'P6'],
];

// Every entry->objective path of the graph was executed end to end by the swarm
// (the campaign's validated kill chains). Enumerated, not typed in.
export function enumerateChains(edges = EDGES) {
  const out = new Map();
  for (const [a, b] of edges) { if (!out.has(a)) out.set(a, []); out.get(a).push(b); }
  const entries = Object.keys(STEPS).filter((s) => s.startsWith('E'));
  const chains = [];
  const walk = (node, path) => {
    if (node.startsWith('O')) { chains.push({ steps: path.slice(0, -1), objective: node }); return; }
    for (const nxt of out.get(node) || []) walk(nxt, [...path, nxt]);
  };
  for (const e of entries) walk(e, [e]);
  const rng = mulberry32(SEED ^ 0x5eed);
  return chains.map((c, i) => ({
    id: 'KC-' + String(i + 1).padStart(2, '0'),
    ...c,
    minutesToObjective: Math.round(6 + c.steps.length * (5 + rng() * 9)),
  }));
}

// ---------------------------------------------------------------------------
// Address canonicalization (for the SSRF callback filter)
// ---------------------------------------------------------------------------
export function parseHost(url) {
  const m = /^[a-z]+:\/\/(\[[^\]]+\]|[^/:?#]+)(?::(\d+))?/i.exec(url || '');
  return m ? { host: m[1].toLowerCase(), port: m[2] || '' } : null;
}

function parseIntPart(p) {
  if (/^0x[0-9a-f]+$/i.test(p)) return parseInt(p, 16);
  if (/^0[0-7]+$/.test(p)) return parseInt(p, 8);
  if (/^\d+$/.test(p)) return parseInt(p, 10);
  return NaN;
}

// Returns a dotted IPv4 string for the many encodings URL parsers accept
// (dotted, decimal, hex, octal, IPv4-mapped IPv6), or null for real hostnames.
export function canonicalIPv4(host) {
  if (!host) return null;
  let h = host;
  if (h.startsWith('[') && h.endsWith(']')) {
    const inner = h.slice(1, -1);
    const mapped = /^::ffff:(.+)$/i.exec(inner);
    if (!mapped) return inner === '::1' ? '127.0.0.1' : null;
    const tail = mapped[1];
    if (/^[0-9a-f]{1,4}:[0-9a-f]{1,4}$/i.test(tail)) {
      const [hi, lo] = tail.split(':').map((x) => parseInt(x, 16));
      return [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.');
    }
    h = tail;
  }
  const parts = h.split('.');
  if (parts.length > 4 || parts.some((p) => p === '')) return null;
  const nums = parts.map(parseIntPart);
  if (nums.some((n) => Number.isNaN(n))) return null;
  let value;
  if (nums.length === 1) value = nums[0];
  else if (nums.length === 2) value = nums[0] * 2 ** 24 + nums[1];
  else if (nums.length === 3) value = nums[0] * 2 ** 24 + nums[1] * 2 ** 16 + nums[2];
  else value = nums[0] * 2 ** 24 + nums[1] * 2 ** 16 + nums[2] * 2 ** 8 + nums[3];
  if (value < 0 || value > 0xffffffff) return null;
  return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join('.');
}

export function isInternalIPv4(ip) {
  if (!ip) return false;
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0;
}

// ---------------------------------------------------------------------------
// Compensating controls (and two permanent fixes) a defender could push.
// `match` is the control's enforcement predicate, evaluated against telemetry.
// `key` (optional) is the dimension a scoped exception can be written on.
// ---------------------------------------------------------------------------
export const CONTROLS = [
  { id: 'C01', name: 'Block callback_url containing 169.254.169.254', integration: 'WAF', via: 'one-click', minutes: 5, steps: ['E1'], src: 'waf.quote-api',
    match: (e) => (e.cb || '').includes('169.254.169.254'), key: null, entity: (e) => e.client },
  { id: 'C02', name: 'Block callback_url resolving to internal ranges', integration: 'WAF', via: 'one-click', minutes: 5, steps: ['E1'], src: 'waf.quote-api',
    match: (e) => { const h = parseHost(e.cb); return !!h && isInternalIPv4(canonicalIPv4(h.host)); },
    key: (e) => `${e.client} -> ${parseHost(e.cb).host}:${parseHost(e.cb).port}`, entity: (e) => e.client },
  { id: 'C03', name: 'Enforce IMDSv2 on quote-api instances', integration: 'AWS', via: 'one-click', minutes: 15, steps: ['P1'], src: 'imds.quote-api',
    match: (e) => e.ver === 'v1', key: null, entity: (e) => `${e.host} ${e.proc}` },
  { id: 'C04', name: 'NetworkPolicy: deny namespace quote to kube-apiserver', integration: 'Kubernetes', via: 'change', minutes: 30, steps: ['P2'], src: 'k8s.audit',
    match: (e) => e.srcNs === 'quote' && e.path === 'pod-network', key: null, entity: (e) => e.srcApp },
  { id: 'C05', name: 'NetworkPolicy: deny app=quote-api to kube-apiserver', integration: 'Kubernetes', via: 'change', minutes: 30, steps: ['P2'], src: 'k8s.audit',
    match: (e) => e.srcApp === 'quote-api' && e.path === 'pod-network', key: null, entity: (e) => e.srcApp },
  { id: 'C06', name: 'Deny API requests as quote-api service account', integration: 'Kubernetes', via: 'change', minutes: 45, steps: ['P3'], src: 'k8s.audit',
    match: (e) => e.sa === 'system:serviceaccount:quote:quote-api', key: null, entity: (e) => e.sa },
  { id: 'C07', name: 'Reject staging-scoped tokens on prod deploy API', integration: 'API gateway', via: 'one-click', minutes: 5, steps: ['P4'], src: 'apigw.deploy',
    match: (e) => e.env === 'prod' && e.scope === 'staging', key: null, entity: (e) => e.client },
  { id: 'C08', name: 'Revoke leaked token stg-7f3a', integration: 'API gateway', via: 'change', minutes: 30, steps: ['P4'], src: 'apigw.deploy',
    match: (e) => e.token === 'stg-7f3a', key: null, entity: (e) => e.client },
  { id: 'C09', name: 'Block /CLAUDE.md and dotfiles on www', integration: 'WAF', via: 'one-click', minutes: 5, steps: ['E2'], src: 'waf.www',
    match: (e) => /^\/(CLAUDE\.md|\.[a-z])/i.test(e.path), key: null, entity: (e) => e.ua },
  { id: 'C10', name: 'Block legacy authentication (all users)', integration: 'Entra ID', via: 'one-click', minutes: 10, steps: ['E3'], src: 'entra.signin',
    match: (e) => e.legacy === true, key: null, entity: (e) => e.user }, // no user exceptions: the attacker picks which account to spray
  { id: 'C11', name: 'Block shell spawned by MFT java service', integration: 'Falcon', via: 'one-click', minutes: 2, steps: ['P5'], src: 'edr.mft-01',
    match: (e) => e.parent === 'java' && ['sh', 'bash', 'dash'].includes(e.child), key: (e) => e.cmd.startsWith('/') ? e.cmd.split(' ')[0] : 'inline: ' + e.child + ' -c', entity: (e) => e.cmd.split(' ')[0] },
  { id: 'C12', name: 'Block LSASS memory reads on jump hosts', integration: 'Falcon', via: 'one-click', minutes: 2, steps: ['P10'], src: 'edr.jump',
    match: (e) => e.access.includes('VM_READ') && !['csfalconservice.exe', 'MsMpEng.exe'].includes(e.proc), key: (e) => e.proc, entity: (e) => e.host },
  { id: 'C13', name: 'Block WebClient NTLM auth from Tier 0/1 servers', integration: 'Falcon', via: 'one-click', minutes: 2, steps: ['P6'], src: 'net.webdav',
    match: (e) => e.tier <= 1, key: (e) => `${e.src} -> ${e.dst}`, entity: (e) => e.src },
  { id: 'C14', name: 'AD CS web enrollment: require EPA, disable NTLM', integration: 'Active Directory', via: 'change', minutes: 120, steps: ['P7'], src: 'iis.certsrv',
    match: (e) => e.auth === 'NTLM', key: null, entity: (e) => e.client },
  { id: 'C15', name: 'svc-backup: AES-only Kerberos, rotate password', integration: 'Active Directory', via: 'change', minutes: 60, steps: ['P8'], src: 'dc.tgs',
    match: (e) => e.svc === 'svc-backup' && e.etype === 'RC4', key: null, entity: (e) => e.client },
  { id: 'C16', name: 'Block SMB from user VLANs to backup subnet', integration: 'Firewall', via: 'change', minutes: 60, steps: ['P9'], src: 'net.backup-smb',
    match: (e) => e.vlan === 'users', key: (e) => e.src, entity: (e) => e.src },
  { id: 'C17', name: 'vCenter: require MFA for every login', integration: 'vCenter', via: 'change', minutes: 90, steps: ['P11'], src: 'vcenter.auth',
    match: (e) => e.mfa === false, key: (e) => `${e.user} from ${e.src}`, entity: (e) => e.user },
  { id: 'C18', name: 'Restrict MFT /admin to corporate ranges', integration: 'WAF', via: 'one-click', minutes: 5, steps: ['E4'], src: 'waf.mft',
    match: (e) => e.path.startsWith('/admin') && e.net !== 'corp', key: (e) => e.srcIp, entity: (e) => e.srcIp },
  { id: 'C19', name: 'Virtual patch: VPN portal traversal signature', integration: 'WAF', via: 'one-click', minutes: 5, steps: ['E5'], src: 'waf.vpn',
    match: (e) => /\/\.\.\//.test(e.path), key: null, entity: (e) => e.srcIp },
  { id: 'C20', name: 'Patch VPN appliance (vendor fix)', integration: 'Change window', via: 'change', minutes: 4320, steps: ['E5'], src: 'waf.vpn',
    match: (e) => /\/\.\.\//.test(e.path), key: null, entity: (e) => e.srcIp },
];

// ---------------------------------------------------------------------------
// Telemetry generator (seeded). Legit events carry attack:false; the swarm's
// recorded attempts carry attack:true and the step they belong to.
// ---------------------------------------------------------------------------
export function generateTelemetry(seed = SEED) {
  const rng = mulberry32(seed);
  const T = {};
  const push = (src, e) => { (T[src] = T[src] || []).push(e); };
  const weekday = (d) => { const dow = (3 + d) % 7; return dow !== 0 && dow !== 6; }; // day 0 = Thu Oct 22 2026

  const partners = ['hooks.northwind-3pl.com', 'api.cargoledger.io', 'edi.portbridge.net', 'notify.haulpath.com', 'webhooks.freightos.example'];
  for (let d = 0; d < DAYS; d++) {
    const wk = weekday(d);
    // quote-api WAF log (1:10 sampled)
    const nq = poissonSample(rng, wk ? 5200 : 2100);
    for (let i = 0; i < nq; i++) {
      const r = rng();
      const client = `${pick(rng, [34, 52, 66, 98, 104, 172])}.${Math.floor(rng() * 255)}.${Math.floor(rng() * 255)}.${Math.floor(rng() * 254) + 1}`;
      if (r < 0.7) push('waf.quote-api', { d, attack: false, client, path: '/v2/quote', cb: '' });
      else push('waf.quote-api', { d, attack: false, client, path: '/v2/quote', cb: `https://${pick(rng, partners)}/quote/${Math.floor(rng() * 1e6)}` });
    }
    const nb = poissonSample(rng, wk ? 64 : 41); // billing-sync posts quotes back to an internal webhook
    for (let i = 0; i < nb; i++) push('waf.quote-api', { d, attack: false, client: '10.40.2.7', path: '/v2/quote', cb: 'http://10.40.3.12:8080/hooks/quote' });

    // instance metadata service on quote-api hosts
    for (let h = 1; h <= 6; h++) {
      const host = `quote-api-${h}`;
      const sdk = poissonSample(rng, 290);
      for (let i = 0; i < sdk; i++) push('imds.quote-api', { d, attack: false, host, proc: 'node (aws-sdk v3)', ver: 'v2' });
      for (let i = 0; i < 288; i++) push('imds.quote-api', { d, attack: false, host, proc: 'fluent-bit 1.8', ver: 'v1' }); // legacy log shipper, every 5 min
    }

    // Kubernetes API audit (requests reaching kube-apiserver)
    const argo = poissonSample(rng, 1150);
    for (let i = 0; i < argo; i++) push('k8s.audit', { d, attack: false, srcNs: 'quote', srcApp: 'argo-rollouts', sa: 'system:serviceaccount:quote:argo-rollouts', path: 'pod-network' });
    const ci = poissonSample(rng, wk ? 380 : 90);
    for (let i = 0; i < ci; i++) push('k8s.audit', { d, attack: false, srcNs: 'ci', srcApp: 'gha-runner', sa: 'system:serviceaccount:ci:deployer', path: 'pod-network' });

    // deploy API gateway
    const dep = poissonSample(rng, wk ? 31 : 6);
    for (let i = 0; i < dep; i++) push('apigw.deploy', { d, attack: false, env: 'prod', scope: 'prod', token: 'prd-19c2', client: 'gha-prod' });
    const stg = poissonSample(rng, wk ? 58 : 14);
    for (let i = 0; i < stg; i++) push('apigw.deploy', { d, attack: false, env: 'staging', scope: 'staging', token: 'stg-7f3a', client: 'gha-staging' });

    // marketing site
    const nw = poissonSample(rng, 3100);
    for (let i = 0; i < nw; i++) push('waf.www', { d, attack: false, path: pick(rng, ['/', '/services', '/quote', '/careers', '/about', '/blog/peak-season-2026']), ua: 'browser' });
    if (rng() < 0.22) push('waf.www', { d, attack: false, path: '/CLAUDE.md', ua: 'Googlebot/2.1' });

    // Entra sign-ins: legacy-auth users (old IMAP/SMTP clients) and modern auth
    const legacyUsers = ['dock-scanner-03', 'mlopez', 'tkhan', 'printer-ops', 'jfischer', 'rnguyen', 'ar-imap-bot', 'sdavis', 'kbrooks'];
    for (const u of legacyUsers) {
      const n = poissonSample(rng, wk ? 5.2 : 2.1);
      for (let i = 0; i < n; i++) push('entra.signin', { d, attack: false, user: u, legacy: true, app: 'IMAP4' });
    }
    const modern = poissonSample(rng, wk ? 2600 : 600);
    for (let i = 0; i < modern; i++) push('entra.signin', { d, attack: false, user: 'user' + Math.floor(rng() * 340), legacy: false, app: 'Browser' });

    // MFT host process telemetry
    for (let i = 0; i < 3; i++) push('edr.mft-01', { d, attack: false, parent: 'java', child: 'sh', cmd: '/opt/mft/bin/post_transfer.sh --batch nightly' });
    const jv = poissonSample(rng, 420);
    for (let i = 0; i < jv; i++) push('edr.mft-01', { d, attack: false, parent: 'java', child: 'java', cmd: 'java -cp mft.jar Worker' });

    // jump hosts: handle opens on lsass
    for (const host of ['jmp-01', 'jmp-02', 'jmp-03']) {
      const s = poissonSample(rng, 40);
      for (let i = 0; i < s; i++) push('edr.jump', { d, attack: false, host, proc: 'csfalconservice.exe', access: 'VM_READ|QUERY' });
      const q = poissonSample(rng, 6);
      for (let i = 0; i < q; i++) push('edr.jump', { d, attack: false, host, proc: 'qualys-agent.exe', access: 'QUERY_LIMITED' });
    }

    // outbound WebDAV (WebClient) authentications from servers
    const prn = poissonSample(rng, wk ? 7.5 : 1.5);
    for (let i = 0; i < prn; i++) push('net.webdav', { d, attack: false, src: 'prn-02', tier: 1, dst: 'sharepoint.meridian.local' });
    const wsd = poissonSample(rng, 140);
    for (let i = 0; i < wsd; i++) push('net.webdav', { d, attack: false, src: 'ws-' + String(100 + Math.floor(rng() * 400)).padStart(4, '0'), tier: 2, dst: 'sharepoint.meridian.local' });

    // AD CS web enrollment
    const ke = poissonSample(rng, wk ? 2.5 : 0.5);
    for (let i = 0; i < ke; i++) push('iis.certsrv', { d, attack: false, auth: 'Kerberos', client: 'helpdesk-portal' });

    // Kerberos TGS requests
    const nas = poissonSample(rng, 4);
    for (let i = 0; i < nas; i++) push('dc.tgs', { d, attack: false, client: 'nas-03', svc: 'svc-backup', etype: 'RC4' });
    const aes = poissonSample(rng, 800);
    for (let i = 0; i < aes; i++) push('dc.tgs', { d, attack: false, client: 'srv-' + Math.floor(rng() * 90), svc: pick(rng, ['svc-backup', 'svc-sql', 'svc-web']), etype: 'AES256' });

    // SMB flows into the backup subnet
    if (wk) { const hd = poissonSample(rng, 2.6); for (let i = 0; i < hd; i++) push('net.backup-smb', { d, attack: false, src: pick(rng, ['hd-01', 'hd-02']), vlan: 'users' }); }
    const ag = poissonSample(rng, 900);
    for (let i = 0; i < ag; i++) push('net.backup-smb', { d, attack: false, src: 'srv-' + Math.floor(rng() * 90), vlan: 'servers' });

    // vCenter logins
    const adm = poissonSample(rng, wk ? 11 : 3);
    for (let i = 0; i < adm; i++) push('vcenter.auth', { d, attack: false, user: pick(rng, ['adm-jlee', 'adm-rpatel', 'adm-okim', 'adm-mshaw', 'adm-tgreen', 'adm-cwu']), mfa: true, src: pick(rng, ['jmp-01', 'jmp-02', 'jmp-03']) });
    for (let i = 0; i < 24; i++) push('vcenter.auth', { d, attack: false, user: 'svc-vmmon', mfa: false, src: 'mon-01' });

    // MFT web traffic
    const corp = poissonSample(rng, wk ? 14 : 2);
    for (let i = 0; i < corp; i++) push('waf.mft', { d, attack: false, path: '/admin/jobs', net: 'corp', srcIp: '10.8.' + Math.floor(rng() * 4) + '.' + Math.floor(rng() * 250) });
    const xfer = poissonSample(rng, 900);
    for (let i = 0; i < xfer; i++) push('waf.mft', { d, attack: false, path: '/transfer/upload', net: 'internet', srcIp: '203.0.113.' + Math.floor(rng() * 250) });
    if (d === 3 || d === 10) push('waf.mft', { d, attack: false, path: '/admin/support', net: 'internet', srcIp: '198.51.100.24' }); // vendor support session

    // VPN portal
    const vp = poissonSample(rng, wk ? 2300 : 700);
    for (let i = 0; i < vp; i++) push('waf.vpn', { d, attack: false, path: pick(rng, ['/remote/login', '/remote/logincheck', '/remote/saml/start', '/portal/home']), srcIp: '73.' + Math.floor(rng() * 255) + '.' + Math.floor(rng() * 255) + '.' + Math.floor(rng() * 254) });
  }

  // ---- the swarm's recorded attempts (campaign window: days 12-13) -------
  const A = (src, step, e) => push(src, { d: 12 + (rng() < 0.5 ? 1 : 0), attack: true, step, ...e });
  for (const cb of ['http://169.254.169.254/latest/meta-data/iam/', 'http://2852039166/latest/meta-data/iam/', 'http://0xA9FEA9FE/latest/api/token', 'http://[::ffff:a9fe:a9fe]/latest/meta-data/', 'http://0251.0376.0251.0376/latest/meta-data/', 'http://169.254.169.254/latest/user-data', 'http://10.100.0.1:443/api/v1/namespaces'])
    A('waf.quote-api', 'E1', { client: '35.203.88.41', path: '/v2/quote', cb });
  for (let i = 0; i < 4; i++) A('imds.quote-api', 'P1', { host: 'quote-api-' + (2 + i), proc: 'node (quote-api)', ver: 'v1' });
  for (let i = 0; i < 6; i++) A('k8s.audit', 'P2', { srcNs: 'quote', srcApp: 'quote-api', sa: 'system:anonymous', path: 'pod-network' });
  for (let i = 0; i < 5; i++) A('k8s.audit', 'P3', { srcNs: 'external', srcApp: 'swarm', sa: 'system:serviceaccount:quote:quote-api', path: 'public-endpoint' });
  for (let i = 0; i < 3; i++) A('apigw.deploy', 'P4', { env: 'prod', scope: 'staging', token: 'stg-7f3a', client: 'swarm' });
  A('waf.www', 'E2', { path: '/CLAUDE.md', ua: 'armadin-swarm' });
  for (const u of ['mlopez', 'tkhan', 'dock-scanner-03', 'sdavis', 'user17', 'user233', 'printer-ops'])
    A('entra.signin', 'E3', { user: u, legacy: true, app: 'SMTP' });
  for (const c of ['sh -c id', 'bash -c whoami', 'sh -c uname -a']) A('edr.mft-01', 'P5', { parent: 'java', child: c.split(' ')[0], cmd: c });
  for (const h of ['jmp-01', 'jmp-02']) A('edr.jump', 'P10', { host: h, proc: 'rundll32.exe', access: 'VM_READ|QUERY' });
  for (const s of ['dc-01', 'dc-02']) A('net.webdav', 'P6', { src: s, tier: 0, dst: 'ws-0412@80/x' });
  for (let i = 0; i < 2; i++) A('iis.certsrv', 'P7', { auth: 'NTLM', client: 'relay:dc-01$' });
  for (let i = 0; i < 3; i++) A('dc.tgs', 'P8', { client: 'ws-0412', svc: 'svc-backup', etype: 'RC4' });
  A('net.backup-smb', 'P9', { src: 'ws-0412', vlan: 'users' });
  for (const u of ['svc-backup', 'adm-jlee']) A('vcenter.auth', 'P11', { user: u, mfa: false, src: 'jmp-02' });
  for (const p of ['/admin/login', '/admin/jobs/run']) A('waf.mft', 'E4', { path: p, net: 'internet', srcIp: '35.203.88.41' });
  for (const p of ['/portal/../../admin/exec', '/remote/../portal/../../admin/exec']) A('waf.vpn', 'E5', { path: p, srcIp: '35.203.88.41' });
  return T;
}
