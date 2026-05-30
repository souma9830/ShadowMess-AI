/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        shadowRed: '#E24B4A',
        shadowAmber: '#EF9F27',
        shadowGreen: '#1D9E75',
        shadowPurple: '#7F77DD',
        shadowGray: '#1a1a1a'
      }
    },
  },
  plugins: [],
}
