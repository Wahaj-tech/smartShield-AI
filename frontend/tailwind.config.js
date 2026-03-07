/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      colors: {
        dark: {
          900: '#020618',
          800: '#0F172B',
          700: 'rgba(15, 23, 43, 0.50)',
          600: '#1D293D',
          500: '#314158',
        },
        'slate-label': '#90A1B9',
        'slate-muted': '#62748E',
        'cyan-accent': '#00D3F2',
        'cyan-dark': '#00B8DB',
        'blue-accent': '#155DFC',
        'blue-light': '#51A2FF',
        'purple-accent': '#C27AFF',
        'red-accent': '#FF6467',
        'green-accent': '#05DF72',
        'yellow-accent': '#FDC700',
      },
    },
  },
  plugins: [],
};
