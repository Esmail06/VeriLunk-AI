const form = document.getElementById('scanForm');
const input = document.getElementById('urlInput');
const result = document.getElementById('result');
const suspiciousWords = ['login','signin','verify','verification','secure','account','update','confirm','password','wallet','banking','bonus','free','recover','unlock','invoice','payment','auth'];
const trustedDomains = ['google.com','microsoft.com','apple.com','amazon.com','github.com','openai.com','paypal.com','gov.uk','gov','edu'];
const protectedBrands = ['google','microsoft','apple','amazon','github','openai','paypal'];
const API_BASE_URL = '';

function normalize(raw) {
  let value = raw.trim();
  if (!/^https?:\/\//i.test(value)) value = `http://${value}`;
  return new URL(value);
}
function isTrusted(host) { return trustedDomains.some(d => host === d || host.endsWith(`.${d}`)); }
function editDistance(left, right) {
  const matrix = Array.from({ length: left.length + 1 }, (_, row) => [row]);
  for (let column = 0; column <= right.length; column += 1) matrix[0][column] = column;
  for (let row = 1; row <= left.length; row += 1) {
    for (let column = 1; column <= right.length; column += 1) {
      matrix[row][column] = left[row - 1] === right[column - 1]
        ? matrix[row - 1][column - 1]
        : Math.min(matrix[row - 1][column - 1], matrix[row - 1][column], matrix[row][column - 1]) + 1;
    }
  }
  return matrix[left.length][right.length];
}
function detectBrandLookalike(host) {
  const labels = host.split('.').filter(label => !['www','com','net','org','edu','gov'].includes(label));
  for (const label of labels) {
    for (const brand of protectedBrands) {
      if (label !== brand && editDistance(label, brand) <= 1) return brand;
    }
  }
  return null;
}
function analyze(raw) {
  const url = normalize(raw); const host = url.hostname.toLowerCase(); const whole = raw.toLowerCase();
  const findings = []; let score = 4;
  const add = (text, weight, type='risk') => { findings.push({text,type}); score += weight; };
  if (url.protocol !== 'https:') add('The URL does not use an encrypted HTTPS connection.', 18);
  else findings.push({text:'The URL uses an encrypted HTTPS connection.',type:'safe'});
  if (raw.length > 75) add('The URL is unusually long, which can hide its real destination.', 12);
  if (host.length > 42) add('The domain name is unusually long or complex.', 10);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add('An IP address is used instead of a recognizable domain name.', 30);
  if ((host.match(/-/g)||[]).length >= 2) add('The domain contains multiple hyphens, a common impersonation pattern.', 10);
  if ((host.match(/\./g)||[]).length >= 3) add('An unusually high number of subdomains was detected.', 12);
  const lookalikeBrand = !isTrusted(host) && detectBrandLookalike(host);
  if (lookalikeBrand) add(`The domain closely resembles ${lookalikeBrand}.com but is not the official domain. This may be a typosquatting attempt.`, 60);
  if (whole.includes('@')) add('The URL contains @, which can be used to obscure the destination.', 25);
  if (whole.includes('xn--')) add('The domain uses internationalized encoding, which can enable visual lookalike attacks.', 25);
  const words = suspiciousWords.filter(w => whole.includes(w));
  if (words.length) add(`Sensitive or urgent wording detected: ${words.slice(0,4).join(', ')}.`, Math.min(28,words.length*7));
  if (url.search.length > 90) add('The query string is unusually long.', 7);
  if (isTrusted(host)) { score -= 20; findings.push({text:'The domain matches a known service in the local trust list.',type:'safe'}); }
  score = Math.max(0,Math.min(100,score));
  const level = score >= 55 ? 'High' : score >= 25 ? 'Medium' : 'Low';
  if (!findings.length) findings.push({text:'No clear phishing signals were found in the URL structure.',type:'safe'});
  return {url,host,score,level,findings};
}
function render(data) {
  const {url,host,score,level,findings} = data;
  const risky = score >= 55, medium = score >=25;
  const color = risky ? '#ff6f72' : medium ? '#ffd36a' : '#47dfc3';
  document.getElementById('score').textContent = score;
  document.getElementById('score').style.color = color;
  document.getElementById('meterFill').style.cssText = `width:${score}%;background:${color}`;
  document.getElementById('verdict').textContent = risky ? 'Potential phishing link' : medium ? 'Additional verification recommended' : 'No strong risk signals found';
  document.getElementById('verdictText').textContent = risky ? 'Do not enter personal data or open this link before verifying the sender.' : medium ? 'Some indicators call for caution. Verify the domain name before proceeding.' : 'The structural analysis found no concerning indicators, but verifying the source still matters.';
  const icon = document.getElementById('verdictIcon'); icon.textContent = risky ? '!' : medium ? '?' : '✓'; icon.style.cssText = `color:${color};background:${color}20`;
  document.getElementById('indicatorCount').textContent = `${findings.length} indicator${findings.length === 1 ? '' : 's'}`;
  document.getElementById('reasons').innerHTML = findings.map(f => `<li class="${f.type}"><span class="dot"></span><span>${f.text}</span></li>`).join('');
  document.getElementById('details').innerHTML = [
    ['Domain',host],['Encryption',url.protocol === 'https:' ? 'HTTPS' : 'Unencrypted (HTTP)'],['URL length',`${url.href.length} characters`],['Risk level',level]
  ].map(([k,v])=>`<div><dt>${k}</dt><dd>${v}</dd></div>`).join('');
  result.hidden=false; result.scrollIntoView({behavior:'smooth',block:'start'});
}
async function checkReachability(rawUrl) {
  const response = await fetch(`${API_BASE_URL}/api/scan`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url: rawUrl})});
  if (!response.ok) throw new Error('The reachability service is unavailable.');
  return response.json();
}
form.addEventListener('submit', async e => {
  e.preventDefault();
  try {
    const analysis = analyze(input.value);
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    button.textContent = 'Checking safely...';
    try {
      const connection = await checkReachability(input.value);
      analysis.findings.push({text: connection.message, type: connection.reachable ? 'safe' : 'risk'});
    } catch {
      analysis.findings.push({text: 'Reachability check is unavailable. The result uses URL structure only.', type: 'risk'});
    } finally {
      button.disabled = false;
      button.innerHTML = 'Scan URL <span>→</span>';
    }
    render(analysis);
  } catch {
    input.focus();
    input.setCustomValidity('Enter a valid URL, for example https://example.com');
    input.reportValidity();
    input.setCustomValidity('');
  }
});
