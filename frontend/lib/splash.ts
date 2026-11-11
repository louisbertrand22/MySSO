import splash from '@/assets/icons/splash-devices.json';

/**
 * iOS launch screens for metadata.appleWebApp.startupImage.
 * Built from the same device list as the generator (assets/icons/generate-splash.mjs),
 * so every <link rel="apple-touch-startup-image"> points to an image that exists.
 * iOS picks the image whose media query matches the device exactly.
 */
export const startupImages = splash.devices.flatMap((d) =>
  (['light', 'dark'] as const).map((theme) => ({
    url: `/splash/${theme}-${d.width * d.ratio}x${d.height * d.ratio}.png`,
    media:
      `(device-width: ${d.width}px) and (device-height: ${d.height}px) and ` +
      `(-webkit-device-pixel-ratio: ${d.ratio}) and (orientation: portrait) and (prefers-color-scheme: ${theme})`,
  }))
);
