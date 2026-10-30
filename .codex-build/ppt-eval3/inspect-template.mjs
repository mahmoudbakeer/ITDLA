import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const runtimeModules = "C:/Users/mahmo/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules";
const skillDir = "C:/Users/mahmo/.codex/plugins/cache/openai-primary-runtime/presentations/26.915.20218/skills/presentations";
const { FileBlob, PresentationFile } = await import(pathToFileURL(path.join(runtimeModules, "@oai/artifact-tool/dist/artifact_tool.mjs")).href);

const sourcePath = "C:/Users/mahmo/Downloads/Eval-3 PPT Format.pptx";
await fs.access(sourcePath);
const presentation = await PresentationFile.importPptx(await FileBlob.load(sourcePath));

const snapshot = await presentation.inspect({
  kind: "slide,textbox,shape,image,table,chart,notes,layout",
  maxChars: 60000,
});
await fs.writeFile("C:/Users/mahmo/dir/Capstone/.codex-build/ppt-eval3/template-inspect.ndjson", snapshot.ndjson, "utf8");

for (let i = 0; i < presentation.slides.items.length; i++) {
  const slide = presentation.slides.items[i];
  const png = await slide.export({ format: "png", scale: 1 });
  await fs.writeFile(
    `C:/Users/mahmo/dir/Capstone/.codex-build/ppt-eval3/template-slide-${String(i + 1).padStart(2, "0")}.png`,
    new Uint8Array(await png.arrayBuffer()),
  );
}

const summary = {
  slideCount: presentation.slides.items.length,
  masters: presentation.masters.items.length,
  slideSize: presentation.slideSize,
};
await fs.writeFile("C:/Users/mahmo/dir/Capstone/.codex-build/ppt-eval3/template-summary.json", JSON.stringify(summary, null, 2), "utf8");
