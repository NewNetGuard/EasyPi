import tailwindcss from 'tailwindcss'
import autoprefixer from 'autoprefixer'
import tailwindcssNesting from 'tailwindcss/nesting/index.js'

/** @type {import('postcss-load-config').Config} */
export default {
  plugins: [tailwindcssNesting, tailwindcss, autoprefixer],
}
