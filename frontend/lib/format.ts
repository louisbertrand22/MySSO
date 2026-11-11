const rtf = new Intl.RelativeTimeFormat('fr', { numeric: 'auto' });

/** "il y a 5 minutes", "hier", "il y a 3 jours"… */
export function timeAgo(date: string | Date): string {
  const seconds = Math.round((new Date(date).getTime() - Date.now()) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 45) return 'à l’instant';
  if (abs < 3600) return rtf.format(Math.round(seconds / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(seconds / 3600), 'hour');
  if (abs < 86400 * 30) return rtf.format(Math.round(seconds / 86400), 'day');
  if (abs < 86400 * 365) return rtf.format(Math.round(seconds / (86400 * 30)), 'month');
  return rtf.format(Math.round(seconds / (86400 * 365)), 'year');
}

export function formatDate(date: string | Date, withTime = false): string {
  return new Date(date).toLocaleString('fr-FR', withTime
    ? { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }
    : { day: 'numeric', month: 'long', year: 'numeric' });
}

/** Rough browser / OS detection from a User-Agent string */
export function parseDevice(ua: string | null): { browser: string; os: string; mobile: boolean } {
  if (!ua) return { browser: 'Navigateur inconnu', os: 'système inconnu', mobile: false };
  let browser = 'Navigateur inconnu';
  if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/OPR\/|Opera\//.test(ua)) browser = 'Opera';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';
  else if (/Chrome\//.test(ua) && !/Chromium/.test(ua)) browser = 'Chrome';
  else if (/Safari\//.test(ua)) browser = 'Safari';
  else if (/node|curl|python|axios|undici/i.test(ua)) browser = 'Application';

  let os = 'système inconnu';
  if (/iPhone|iPad/.test(ua)) os = 'iOS';
  else if (/Android/.test(ua)) os = 'Android';
  else if (/Windows/.test(ua)) os = 'Windows';
  else if (/Macintosh|Mac OS X/.test(ua)) os = 'macOS';
  else if (/Linux/.test(ua)) os = 'Linux';

  return { browser, os, mobile: /iPhone|Android|Mobile/.test(ua) };
}
