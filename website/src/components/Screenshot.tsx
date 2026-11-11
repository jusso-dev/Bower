import useBaseUrl from "@docusaurus/useBaseUrl";
import ThemedImage from "@theme/ThemedImage";

// A console screenshot in the site's current theme, from website/static/img/console.
// Captured by ui/Bower.Management.Web/e2e/docs-gallery.spec.ts on synthetic preview data.
export default function Screenshot({ name, alt }: { name: string; alt: string }) {
  return (
    <figure className="bower-screenshot">
      <ThemedImage
        alt={alt}
        width={1440}
        height={900}
        sources={{
          light: useBaseUrl(`/img/console/${name}-light.png`),
          dark: useBaseUrl(`/img/console/${name}-dark.png`)
        }}
      />
    </figure>
  );
}
