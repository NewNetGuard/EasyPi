/**
 * Generate PNG icons from SVG for PWA
 * 
 * Run: node generate-png-icons.cjs
 */

const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const iconsDir = path.join(__dirname, 'public', 'icons');

// Icon sizes for PWA
const sizes = [72, 96, 128, 144, 152, 192, 384, 512];

// Create EasyPi icon SVG programmatically
function createIconSVG(size) {
  const radius = Math.round(size * 0.225); // rx="45" at 200 = 22.5%
  const scale = size / 200;
  
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 200 200">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0c1445;stop-opacity:1" />
      <stop offset="40%" style="stop-color:#0c1445;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#EF4444;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect width="200" height="200" rx="45" fill="url(#grad)"/>
  <circle cx="100" cy="100" r="65" fill="none" stroke="white" stroke-width="3" opacity="0.3"/>
  <text x="100" y="88" font-family="Arial, sans-serif" font-size="32" font-weight="700" fill="white" text-anchor="middle" letter-spacing="2">Easy</text>
  <text x="100" y="132" font-family="Georgia, serif" font-size="52" font-weight="400" fill="#EF4444" text-anchor="middle">π</text>
</svg>`;
}

// Create maskable icon with more padding for safe area
function createMaskableSVG(size) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 200 200">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0c1445;stop-opacity:1" />
      <stop offset="40%" style="stop-color:#0c1445;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#EF4444;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect width="200" height="200" fill="url(#grad)"/>
  <circle cx="100" cy="100" r="50" fill="none" stroke="white" stroke-width="2.5" opacity="0.3"/>
  <text x="100" y="92" font-family="Arial, sans-serif" font-size="26" font-weight="700" fill="white" text-anchor="middle" letter-spacing="1.5">Easy</text>
  <text x="100" y="125" font-family="Georgia, serif" font-size="40" font-weight="400" fill="#EF4444" text-anchor="middle">π</text>
</svg>`;
}

async function generateIcons() {
  console.log('Generating PNG icons for PWA...\n');
  
  // Ensure icons directory exists
  if (!fs.existsSync(iconsDir)) {
    fs.mkdirSync(iconsDir, { recursive: true });
  }
  
  // Generate standard icons
  for (const size of sizes) {
    const svg = createIconSVG(size);
    const outputPath = path.join(iconsDir, `icon-${size}x${size}.png`);
    
    try {
      await sharp(Buffer.from(svg))
        .png()
        .toFile(outputPath);
      console.log(`✓ Generated: icon-${size}x${size}.png`);
    } catch (error) {
      console.error(`✗ Failed to generate icon-${size}x${size}.png:`, error.message);
    }
  }
  
  // Generate maskable icon (512x512 with safe area)
  const maskableSvg = createMaskableSVG(512);
  const maskablePath = path.join(iconsDir, 'maskable-icon-512x512.png');
  
  try {
    await sharp(Buffer.from(maskableSvg))
      .png()
      .toFile(maskablePath);
    console.log('✓ Generated: maskable-icon-512x512.png');
  } catch (error) {
    console.error('✗ Failed to generate maskable icon:', error.message);
  }
  
  // Generate badge icon (72x72)
  const badgeSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="72" height="72" viewBox="0 0 200 200">
    <defs>
      <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:#0c1445"/>
        <stop offset="40%" style="stop-color:#0c1445"/>
        <stop offset="100%" style="stop-color:#EF4444"/>
      </linearGradient>
    </defs>
    <circle cx="100" cy="100" r="100" fill="url(#grad)"/>
    <text x="100" y="115" font-family="Georgia, serif" font-size="80" font-weight="400" fill="#EF4444" text-anchor="middle">π</text>
  </svg>`;
  
  const badgePath = path.join(iconsDir, 'badge-72x72.png');
  try {
    await sharp(Buffer.from(badgeSvg))
      .png()
      .toFile(badgePath);
    console.log('✓ Generated: badge-72x72.png');
  } catch (error) {
    console.error('✗ Failed to generate badge icon:', error.message);
  }
  
  // Generate Apple touch icon (180x180)
  const appleSvg = createIconSVG(180);
  const applePath = path.join(iconsDir, 'apple-touch-icon.png');
  try {
    await sharp(Buffer.from(appleSvg))
      .png()
      .toFile(applePath);
    console.log('✓ Generated: apple-touch-icon.png');
  } catch (error) {
    console.error('✗ Failed to generate apple touch icon:', error.message);
  }
  
  // Generate favicon (32x32)
  const faviconSvg = createIconSVG(32);
  const faviconPath = path.join(iconsDir, 'favicon-32x32.png');
  try {
    await sharp(Buffer.from(faviconSvg))
      .png()
      .toFile(faviconPath);
    console.log('✓ Generated: favicon-32x32.png');
  } catch (error) {
    console.error('✗ Failed to generate favicon:', error.message);
  }
  
  console.log('\n✅ All PNG icons generated successfully!');
}

generateIcons().catch(console.error);
