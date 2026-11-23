/**
 * PWA Icon Generator Script
 * 
 * Run this script with Node.js to generate placeholder icons.
 * For production, use a proper image generator tool.
 * 
 * Usage: node generate-icons.js
 */

const fs = require('fs');
const path = require('path');

// SVG template for generating icons
const generateSVG = (size, withText = true) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">
  <defs>
    <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0ea5e9;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#8b5cf6;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect width="${size}" height="${size}" rx="${Math.round(size * 0.15)}" fill="url(#grad1)"/>
  <g fill="#ffffff" transform="translate(${size * 0.1}, ${size * 0.1}) scale(${size * 0.8 / 512})">
    <circle cx="256" cy="180" r="70" opacity="0.95"/>
    <circle cx="200" cy="260" r="45" opacity="0.85"/>
    <circle cx="312" cy="260" r="45" opacity="0.85"/>
    <circle cx="176" cy="340" r="35" opacity="0.75"/>
    <circle cx="256" cy="355" r="35" opacity="0.75"/>
    <circle cx="336" cy="340" r="35" opacity="0.75"/>
    <rect x="248" y="90" width="16" height="35" rx="4"/>
    <ellipse cx="280" cy="100" rx="22" ry="14" transform="rotate(30 280 100)"/>
  </g>
  ${withText && size >= 128 ? `<text x="${size/2}" y="${size * 0.92}" text-anchor="middle" font-family="system-ui, -apple-system, sans-serif" font-size="${Math.max(12, size * 0.08)}" font-weight="600" fill="#ffffff" opacity="0.9">EasyPi</text>` : ''}
</svg>`;

// Icon sizes needed for PWA
const sizes = [72, 96, 128, 144, 152, 192, 384, 512];

const iconsDir = __dirname;

// Generate SVG files (which can be converted to PNG using tools)
sizes.forEach(size => {
  const svg = generateSVG(size, size >= 128);
  const filename = path.join(iconsDir, `icon-${size}x${size}.svg`);
  fs.writeFileSync(filename, svg);
  console.log(`Generated: icon-${size}x${size}.svg`);
});

// Generate maskable icon (with extra padding for safe area)
const maskableSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <rect width="512" height="512" fill="#0ea5e9"/>
  <g fill="#ffffff" transform="translate(96, 96) scale(0.625)">
    <circle cx="256" cy="180" r="70" opacity="0.95"/>
    <circle cx="200" cy="260" r="45" opacity="0.85"/>
    <circle cx="312" cy="260" r="45" opacity="0.85"/>
    <circle cx="176" cy="340" r="35" opacity="0.75"/>
    <circle cx="256" cy="355" r="35" opacity="0.75"/>
    <circle cx="336" cy="340" r="35" opacity="0.75"/>
    <rect x="248" y="90" width="16" height="35" rx="4"/>
    <ellipse cx="280" cy="100" rx="22" ry="14" transform="rotate(30 280 100)"/>
  </g>
</svg>`;
fs.writeFileSync(path.join(iconsDir, 'maskable-icon-512x512.svg'), maskableSVG);
console.log('Generated: maskable-icon-512x512.svg');

// Generate badge icon for notifications
const badgeSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 72 72" width="72" height="72">
  <circle cx="36" cy="36" r="32" fill="#0ea5e9"/>
  <g fill="#ffffff" transform="translate(12, 12) scale(0.67)">
    <circle cx="36" cy="28" r="14"/>
    <circle cx="28" cy="44" r="10"/>
    <circle cx="44" cy="44" r="10"/>
  </g>
</svg>`;
fs.writeFileSync(path.join(iconsDir, 'badge-72x72.svg'), badgeSVG);
console.log('Generated: badge-72x72.svg');

// Generate shortcut icons
const shortcuts = ['dashboard', 'terminal', 'vpn'];
const shortcutIcons = {
  dashboard: `<path d="M3 3h7v7H3V3zm11 0h7v7h-7V3zM3 14h7v7H3v-7zm11 0h7v7h-7v-7z"/>`,
  terminal: `<path d="M4 3h16a1 1 0 011 1v16a1 1 0 01-1 1H4a1 1 0 01-1-1V4a1 1 0 011-1zm1 4l4 4-4 4m5 0h6"/>`,
  vpn: `<path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>`
};

shortcuts.forEach(name => {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96" width="96" height="96">
    <rect width="96" height="96" rx="16" fill="#0ea5e9"/>
    <g fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" transform="translate(24, 24) scale(2)">
      ${shortcutIcons[name]}
    </g>
  </svg>`;
  fs.writeFileSync(path.join(iconsDir, `shortcut-${name}.svg`), svg);
  console.log(`Generated: shortcut-${name}.svg`);
});

console.log('\n✅ All SVG icons generated!');
console.log('\nTo convert to PNG, use one of these methods:');
console.log('1. ImageMagick: convert icon-192x192.svg icon-192x192.png');
console.log('2. Inkscape: inkscape icon-192x192.svg -o icon-192x192.png');
console.log('3. Online: https://cloudconvert.com/svg-to-png');
