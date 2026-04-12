/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./internal/gateway/web/templates/**/*.html"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: "#161b22",
          2: "#1e2530",
        },
        border: "#30363d",
      },
    },
  },
  plugins: [],
};
