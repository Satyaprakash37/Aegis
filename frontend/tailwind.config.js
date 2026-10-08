/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0b1220',
        surface: '#0f172a',
        card: '#111a2e',
        sidebar: '#0a0f1c',
        border: 'rgba(255, 255, 255, 0.07)',
        primary: {
          DEFAULT: '#3B82F6',
          hover: '#2563EB',
        },
        cyber: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#10B981',
          accent: '#06B6D4',
        }
      }
    },
  },
  plugins: [],
}
