/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        obsidian: {
          950: '#030508',
          900: '#06090F',
          850: '#0A0D15',
          800: '#0F131D',
        },
        graphite: {
          900: '#141824',
          800: '#1C2232',
          700: '#262E42',
          600: '#343D56',
        },
        smoked: {
          glass: 'rgba(15, 20, 32, 0.72)',
          border: 'rgba(255, 255, 255, 0.08)',
          highlight: 'rgba(255, 255, 255, 0.15)',
        },
        platinum: {
          100: '#FFFFFF',
          200: '#F1F5F9',
          300: '#E2E8F0',
          400: '#CBD5E1',
          500: '#94A3B8',
          600: '#64748B',
        },
        chrome: {
          light: '#E6EDF5',
          metallic: '#A9B7C6',
          dark: '#5C6779',
        },
        status: {
          verified: '#F1F5F9', // Platinum/white
          pending: '#64748B',  // Muted grey
          warning: '#F59E0B',  // Muted amber
          critical: '#EF4444', // Controlled red
          anchored: '#38BDF8', // Metallic ice silver/cyan ledger indicator
        }
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        'glow-platinum': '0 0 25px rgba(226, 232, 240, 0.15)',
        'glow-amber': '0 0 25px rgba(245, 158, 11, 0.2)',
        'glow-red': '0 0 25px rgba(239, 68, 68, 0.25)',
        'glow-chrome': '0 0 35px rgba(169, 183, 198, 0.2)',
      }
    },
  },
  plugins: [],
}
