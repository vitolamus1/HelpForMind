/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",
    // Ważne: Dodaj również samego globals.css, jeśli używasz w nim @apply
    "./styles/globals.css",
    // Lub ogólniejsze:
    // "./styles/**/*.{css,scss}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}