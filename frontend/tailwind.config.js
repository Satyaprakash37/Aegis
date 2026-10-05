/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0B0F17',
        surface: '#111827',
        card: '#161F30',
        border: '#1F2937',
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
