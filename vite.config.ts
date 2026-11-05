import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig } from 'vite';
import { VitePWA } from 'vite-plugin-pwa';

export default defineConfig(() => {
  return {
    plugins: [
      react(),
      tailwindcss(),
      VitePWA({
        registerType: 'autoUpdate',
        includeAssets: [
          'icon.svg',
          'assets/aistudio/Logotipo_Moda_Vintage_Minimalista_Beige_y_Azul_8f32ae19.png',
        ],
        manifest: {
          id: '/',
          name: 'CreciSano — Recetas Saludables',
          short_name: 'CreciSano',
          description:
            'Plataforma digital de recetas saludables, prácticas y económicas para madres y familias.',
          theme_color: '#1B4332',
          background_color: '#F6F3EB',
          display: 'standalone',
          start_url: '/',
          scope: '/',
          icons: [
            {
              src: '/assets/aistudio/Logotipo_Moda_Vintage_Minimalista_Beige_y_Azul_8f32ae19.png',
              sizes: '192x192',
              type: 'image/png',
              purpose: 'any',
            },
            {
              src: '/assets/aistudio/Logotipo_Moda_Vintage_Minimalista_Beige_y_Azul_8f32ae19.png',
              sizes: '512x512',
              type: 'image/png',
              purpose: 'any',
            },
          ],
        },
        workbox: {
          globPatterns: ['**/*.{js,css,html,ico,png,svg,jpg,webp,woff,woff2}'],
          navigateFallbackDenylist: [/^\/api\//, /^\/uploads\//],
        },
        devOptions: {
          enabled: true,
          type: 'module',
        },
      }),
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
