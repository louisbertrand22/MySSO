#!/usr/bin/env node
/**
 * Generates the iOS launch screens (apple-touch-startup-image) into public/splash/.
 * One PNG per device in splash-devices.json, in a light and a dark variant:
 * the app icon centred on the app background colour (same colours as the first page,
 * so the launch screen blends into the app without a white flash).
 *
 * Requires rsvg-convert (librsvg). Usage: node frontend/assets/icons/generate-splash.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '../../public/splash');
const { devices, themes } = JSON.parse(readFileSync(join(here, 'splash-devices.json'), 'utf8'));

// Inner content of the "any" icon (rounded tile), reused as a nested SVG
const iconSvg = readFileSync(join(here, 'icon.svg'), 'utf8').replace(/<!--[\s\S]*?-->/g, '').trim();

mkdirSync(out, { recursive: true });
for (const f of readdirSync(out)) if (f.endsWith('.png')) rmSync(join(out, f));

const tmp = join(tmpdir(), `mysso-splash-${process.pid}.svg`);
let count = 0;

for (const d of devices) {
  const w = d.width * d.ratio;
  const h = d.height * d.ratio;
  // Icon: 96pt on phones, 128pt on tablets (close to native launch screens)
  const iconPt = d.width >= 700 ? 128 : 96;
  const size = iconPt * d.ratio;
  const x = Math.round((w - size) / 2);
  const y = Math.round((h - size) / 2);

  for (const [theme, bg] of Object.entries(themes)) {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
  <rect width="${w}" height="${h}" fill="${bg}"/>
  <svg x="${x}" y="${y}" width="${size}" height="${size}" viewBox="0 0 512 512">${iconSvg.replace(/^<svg[^>]*>|<\/svg>$/g, '')}</svg>
</svg>`;
    writeFileSync(tmp, svg);
    execFileSync('rsvg-convert', ['-w', String(w), '-h', String(h), tmp, '-o', join(out, `${theme}-${w}x${h}.png`)]);
    count++;
  }
}
rmSync(tmp, { force: true });
console.log(`${count} launch screens written to ${out}`);
