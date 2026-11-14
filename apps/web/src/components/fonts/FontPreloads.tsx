/**
 * Emits `<link rel="preload">` for self-hosted webfonts.
 *
 * `next/font/google` used to generate these automatically for every font file
 * whose subset matched the loader's `subsets` option, scoped to the routes
 * that imported the face. Self-hosting the fonts removed the build-time fetch
 * and the generated preload tags along with it, so they are emitted here from
 * the lists `scripts/generate_web_font_css.py` derives from the font manifest.
 *
 * React hoists these into `<head>`. `crossOrigin` is required even though the
 * files are same-origin: fonts are always fetched in CORS mode, so a preload
 * without it is discarded and the file is requested a second time.
 */
export function FontPreloads({ hrefs }: { hrefs: readonly string[] }) {
  return (
    <>
      {hrefs.map((href) => (
        <link
          key={href}
          rel="preload"
          as="font"
          type="font/woff2"
          href={href}
          crossOrigin="anonymous"
        />
      ))}
    </>
  );
}
