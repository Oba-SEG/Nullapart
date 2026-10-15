import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const brandRoot = join(scriptDir, "..", "public", "brand");
const manifest = JSON.parse(
  readFileSync(join(brandRoot, "asset-manifest.json"), "utf8"),
);

function pngDimensions(file) {
  const bytes = readFileSync(file);
  if (bytes.toString("ascii", 1, 4) !== "PNG")
    throw new Error(`${file} is not a PNG`);
  return [bytes.readUInt32BE(16), bytes.readUInt32BE(20)];
}

function svgDimensions(file) {
  const source = readFileSync(file, "utf8");
  const width = /\bwidth="(\d+)"/.exec(source)?.[1];
  const height = /\bheight="(\d+)"/.exec(source)?.[1];
  if (!width || !height)
    throw new Error(`${file} must declare numeric SVG dimensions`);
  return [Number(width), Number(height)];
}

for (const asset of manifest.assets) {
  const file = join(brandRoot, asset.file);
  if (!existsSync(file))
    throw new Error(`Missing branded asset: ${asset.file}`);
  const match = /^(\d+)x(\d+)$/.exec(asset.dimensions);
  if (match) {
    const [width, height] = asset.file.endsWith(".svg")
      ? svgDimensions(file)
      : pngDimensions(file);
    if (width !== Number(match[1]) || height !== Number(match[2])) {
      throw new Error(
        `Dimension mismatch for ${asset.file}: expected ${asset.dimensions}, got ${width}x${height}`,
      );
    }
  }
}

if (manifest.assets.length !== 30) {
  throw new Error(
    `Expected 30 contact-sheet categories, found ${manifest.assets.length}`,
  );
}

globalThis.console.log(
  `Verified ${manifest.assets.length} branded assets from the reference manifest.\n`,
);
