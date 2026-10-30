import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";

const workspaceDir = "C:/Users/mahmo/dir/Capstone";
const SKILL_DIR = "C:/Users/mahmo/.codex/plugins/cache/openai-primary-runtime/presentations/26.915.20218/skills/presentations";
const RUNTIME_PYTHON = "C:/Users/mahmo/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe";
const runtimeModules = "C:/Users/mahmo/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules";
const TMP_DIR = path.join(workspaceDir, ".codex-build/ppt-eval3");
const OUTPUT_DIR = path.join(workspaceDir, "output");
const FINAL_PPTX = path.join(OUTPUT_DIR, "Eval-3_Final_Project_Evaluation_Cybersecurity_v2.pptx");
const sourceTemplatePath = "C:/Users/mahmo/Downloads/Eval-3 PPT Format.pptx";
const logoPath = path.join(TMP_DIR, "template-unzipped/ppt/media/image1.png");
process.env.RUNTIME_NODE_MODULES = runtimeModules;

const { Presentation, PresentationFile } = await import(pathToFileURL(path.join(runtimeModules, "@oai/artifact-tool/dist/artifact_tool.mjs")).href);
const { makeNativeBulletParagraphs, finalizePresentation } = await import(
  pathToFileURL(path.join(SKILL_DIR, "container_tools/artifact_tool_utils.mjs")).href,
);

await fs.mkdir(TMP_DIR, { recursive: true });
await fs.mkdir(OUTPUT_DIR, { recursive: true });

const W = 960;
const H = 720;
const presentation = Presentation.create({ slideSize: { width: W, height: H } });
const logoBytes = await fs.readFile(logoPath);

const fonts = {
  title: "Times New Roman",
  body: "Arial",
};

function addTextbox(slide, text, position, style = {}) {
  const box = slide.shapes.add({
    geometry: "textbox",
    position,
    fill: "none",
    line: { fill: "none", width: 0 },
  });
  box.text = text;
  const textStyle = {
    typeface: style.typeface ?? fonts.body,
    fontSize: style.fontSize ?? 22,
    bold: style.bold ?? false,
    italic: style.italic ?? false,
    color: style.color ?? "#000000",
    autoFit: style.autoFit ?? "none",
  };
  box.text.style = textStyle;
  return box;
}

function addSlideNumber(slide, num) {
  addTextbox(slide, String(num), { left: 878, top: 680, width: 40, height: 24 }, {
    fontSize: 18,
    color: "#808080",
    align: "center",
  });
}

function addTopRule(slide) {
  slide.shapes.add({
    geometry: "rect",
    position: { left: 0, top: 0, width: W, height: 2 },
    fill: "#000000",
    line: { fill: "#000000", width: 0 },
  });
}

function contentSlide(title, slideNo, opts = {}) {
  const slide = presentation.slides.add();
  slide.background.fill = "#FFFFFF";
  addTopRule(slide);
  addTextbox(slide, title, { left: 40, top: 28, width: 880, height: opts.titleHeight ?? 54 }, {
    fontSize: opts.titleSize ?? 30,
    bold: true,
    align: "center",
  });
  addSlideNumber(slide, slideNo);
  return slide;
}

function sectionBlock(slide, heading, bullets, x, y, w, h, opts = {}) {
  addTextbox(slide, heading, { left: x, top: y, width: w, height: opts.headingHeight ?? 28 }, {
    fontSize: opts.headingSize ?? 18,
    bold: true,
  });
  const body = slide.shapes.add({
    geometry: "textbox",
    position: { left: x + 16, top: y + (opts.headingHeight ?? 28), width: w - 12, height: h - (opts.headingHeight ?? 28) },
    fill: "none",
    line: { fill: "none", width: 0 },
  });
  body.text = makeNativeBulletParagraphs(bullets, {
    marginLeftPoints: opts.marginLeftPoints ?? 16,
    hangingPoints: opts.hangingPoints ?? 8,
    spaceAfterPoints: opts.spaceAfterPoints ?? 5,
  });
  body.text.style = {
    typeface: fonts.body,
    fontSize: opts.fontSize ?? 17,
    color: "#000000",
    autoFit: "none",
  };
  return body;
}

function addTable(slide, values, left, top, width, height, opts = {}) {
  const table = slide.tables.add({
    rows: values.length,
    columns: values[0].length,
    left,
    top,
    width,
    height,
    values,
    columnTracks: opts.columnTracks,
  });
  table.borders.assign({ style: "solid", fill: "#000000", width: 1 });
  table.cells.block({ row: 0, column: 0, rowCount: values.length, columnCount: values[0].length }).assign({
    textStyle: { typeface: fonts.body, fontSize: opts.fontSize ?? 13, color: "#000000" },
    margins: { left: 6, right: 6, top: 3, bottom: 3 },
  });
  if (opts.headerRow) {
    const header = table.cells.block({ row: 0, column: 0, rowCount: 1, columnCount: values[0].length });
    header.fill = "#EDEDED";
    header.textStyle.bold = true;
  }
  return table;
}

function addArrow(slide, x1, y1, x2, y2) {
  const left = Math.min(x1, x2);
  const top = Math.min(y1, y2) - 8;
  const width = Math.max(18, Math.abs(x2 - x1));
  addTextbox(slide, "→", { left, top: top - 4, width, height: 28 }, {
    fontSize: 20,
    bold: true,
    align: "center",
  });
}

function addFlowBox(slide, text, left, top, width, height, opts = {}) {
  const shape = slide.shapes.add({
    geometry: "rect",
    position: { left, top, width, height },
    fill: "#FFFFFF",
    line: { style: "solid", fill: "#000000", width: 1.2 },
  });
  shape.text = text;
  shape.text.style = {
    typeface: fonts.body,
    fontSize: opts.fontSize ?? 13,
    bold: opts.bold ?? false,
    color: "#000000",
    autoFit: "none",
  };
  return shape;
}

// 1. Title slide
{
  const slide = presentation.slides.add();
  slide.background.fill = "#FFFFFF";
  slide.images.add({
    blob: logoBytes,
    contentType: "image/png",
    alt: "Sharda University logo",
    fit: "contain",
    position: { left: 277.5, top: 15, width: 413.21, height: 179.98 },
  });
  addTextbox(slide, "Intelligent Threat Detection and Log Analysis Platform\nReasoning Over Incomplete Security Telemetry", { left: 50, top: 214, width: 860, height: 84 }, {
    typeface: fonts.title,
    fontSize: 25,
    bold: true,
    align: "center",
  });
  addTextbox(slide, "Team Members:", { left: 30, top: 350, width: 240, height: 28 }, { typeface: fonts.title, fontSize: 18, bold: true });
  addTextbox(slide, "Jaffar Jned, Mahmoud Bakir", { left: 30, top: 388, width: 250, height: 58 }, { typeface: fonts.title, fontSize: 16 });
  addTextbox(slide, "Mentor/Guide:", { left: 335, top: 350, width: 260, height: 28 }, { typeface: fonts.title, fontSize: 18, bold: true });
  addTextbox(slide, "Dr. Deepthi P S", { left: 335, top: 388, width: 260, height: 58 }, { typeface: fonts.title, fontSize: 16 });
  addTextbox(slide, "Department & Institution:", { left: 630, top: 350, width: 280, height: 28 }, { typeface: fonts.title, fontSize: 18, bold: true });
  addTextbox(slide, "Department of Computer Science and Engineering,\nSchool of Computer Science and Engineering,\nSharda University, Greater Noida, India", { left: 630, top: 388, width: 300, height: 100 }, { typeface: fonts.title, fontSize: 15 });
  addTextbox(slide, "DEPARTMENT OF COMPUTER SCIENCE & ENGINEERING\nSCHOOL OF COMPUTER SCIENCE AND ENGINEERING\nOct 2026", { left: 80, top: 555, width: 800, height: 92 }, {
    typeface: fonts.title,
    fontSize: 24,
    align: "center",
  });
}

// 2. Introduction, split for readability
{
  const slide = contentSlide("2. Introduction", 2);
  sectionBlock(slide, "Project Overview:", [
    "A security telemetry platform that ingests host audit data, detects suspicious activity, and reconstructs attack chains — with its core focus on what happens when that telemetry is incomplete.",
    "Built around five integrated capabilities: normalization, context-aware detection, correlation/chain reconstruction, reasoning over incomplete telemetry, and evidence-based investigation.",
  ], 48, 100, 864, 230, { fontSize: 20, spaceAfterPoints: 8 });
  sectionBlock(slide, "Problem Statement:", [
    "Provenance-based intrusion detection systems (PIDSes) are built and evaluated assuming the telemetry they receive is a complete record of host activity.",
    "Real deployments lose telemetry constantly — agent crashes, buffer overflow under load, sampling, misconfiguration — not just through attacker tampering.",
    "No existing system measures how badly detection and reconstruction degrade under this loss, or flags to an analyst where its own evidence is incomplete.",
  ], 48, 350, 864, 250, { fontSize: 19, spaceAfterPoints: 7 });
}

{
  const slide = contentSlide("2. Introduction", 3);
  sectionBlock(slide, "Objectives:", [
    "Build a working pipeline: normalization → context-aware detection → correlation/chain reconstruction, reusing published methodology.",
    "Design and implement a reproducible telemetry loss-injection (ablation) harness.",
    "Design, implement, and evaluate a statistical gap-localization method that flags where evidence is likely missing, without fabricating what that evidence was.",
    "Present chains, supporting evidence, and flagged gaps in a traceable, analyst-facing output.",
  ], 48, 100, 864, 300, { fontSize: 18.5, spaceAfterPoints: 6 });
  sectionBlock(slide, "Scope of the Project:", [
    "In scope: one telemetry source/OS family, offline/batch analysis, reused detection+correlation methodology, original loss-injection and gap-localization work, minimal evidence view.",
    "Out of scope: real-time streaming, multi-tenancy/auth, SOAR/response actions, cloud integrations, novel detection algorithms, LLM-based reasoning.",
  ], 48, 430, 864, 160, { fontSize: 18.5, spaceAfterPoints: 7 });
}

// 3. Functional Specifications
{
  const slide = contentSlide("3. Functional Specifications (CO4)", 4, { titleSize: 28 });
  sectionBlock(slide, "Identified System Requirements:", [
    "Ingest and normalize raw provenance telemetry into typed entities/events.",
    "Score entities/time-windows for anomalousness using context (identity, host, time, process lineage).",
    "Correlate anomalous events into candidate attack chains.",
    "Inject controlled, reproducible telemetry loss for experimentation, with a hidden ablation manifest.",
    "Localize likely gap locations in a chain and assign a confidence score.",
    "Render chains, evidence, and gaps in an analyst-readable view.",
  ], 48, 100, 864, 480, { fontSize: 20, spaceAfterPoints: 9 });
}

{
  const slide = contentSlide("3. Functional Specifications (CO4)", 5, { titleSize: 28 });
  addTextbox(slide, "Functional Requirements List:", { left: 48, top: 95, width: 864, height: 28 }, { fontSize: 18, bold: true });
  addTable(slide, [
    ["FR1", "Parse raw dataset records into the internal event/entity schema"],
    ["FR2", "Assign anomaly scores to entities/windows using a reused detector"],
    ["FR3", "Build candidate attack-chain graphs from scored events"],
    ["FR4", "Remove known events from ground-truth chains under a defined loss mechanism and rate"],
    ["FR5", "Flag chain locations where observed continuity is statistically implausible, with confidence C(u,v)"],
    ["FR6", "Display chain + evidence + gaps, every displayed claim traceable to a concrete evidence object"],
  ], 54, 138, 852, 410, { fontSize: 14.5, columnTracks: [{ mode: "fixed", value: 74 }, { mode: "fr", value: 1 }] });
}

{
  const slide = contentSlide("3. Functional Specifications (CO4)", 6, { titleSize: 28 });
  sectionBlock(slide, "Non-Functional Requirements:", [
    "Reproducibility: every experimental run re-derivable from a fixed seed and config.",
    "Explainability: no unsupported claims in investigator output.",
    "Maintainability: pipeline runnable end-to-end from a single entry point.",
    "Feasibility: runs on available team hardware within dataset constraints.",
  ], 48, 100, 864, 260, { fontSize: 19.5, spaceAfterPoints: 8 });
  sectionBlock(slide, "Quantification and Completeness Analysis:", [
    "Detection reproduced within a stated tolerance of the published baseline's reported performance on the unablated dataset.",
    "Gap-localization precision/recall measured against baselines (never-predict, random, fixed-threshold heuristic).",
    "[PLACEHOLDER — insert actual measured numbers once available]",
  ], 48, 395, 864, 220, { fontSize: 19, spaceAfterPoints: 8 });
}

// 4. SDLC
{
  const slide = contentSlide("4. Selection of Computing Framework / SDLC Model (CO4)", 7, { titleSize: 25 });
  sectionBlock(slide, "Evaluation of Different SDLC Models:", [
    "Waterfall: rejected — the research questions (RQ1–RQ3) depend on experimental results that reshape later design decisions; a rigid sequential model doesn't accommodate that feedback.",
    "Agile/Scrum (full team-of-many ceremonies): rejected — overhead inappropriate for a two-person team.",
    "Iterative/incremental research-engineering model: selected.",
  ], 48, 90, 864, 235, { fontSize: 17.5, spaceAfterPoints: 7 });
  sectionBlock(slide, "Justification for Selected Framework/Model:", [
    "Matches the phase structure already established: Research/Problem Definition → Architecture → Component Implementation → Experiments → Evaluation, with each phase producing a working, testable increment.",
    "Allows RQ1 (degradation characterization) to be fully resolved before RQ2 (gap localization) is attempted, so a safe result exists even if later phases run short on time.",
  ], 48, 335, 864, 190, { fontSize: 17.5, spaceAfterPoints: 7 });
  sectionBlock(slide, "Implementation Strategy:", [
    "Build and validate one component at a time against a smaller slice of data before scaling to the full dataset.",
    "Gate each phase on a concrete validation criterion (e.g., reproduced baseline performance) before proceeding.",
  ], 48, 545, 864, 115, { fontSize: 17.5, spaceAfterPoints: 6 });
}

// 5. Tools
{
  const slide = contentSlide("5. Use of Latest Design Tools (CO5)", 8, { titleSize: 28 });
  sectionBlock(slide, "Tools and Technologies Used:", [
    "Dataset/tooling: DARPA TC E3, accessed via PIDSMaker (bundles reused baseline PIDS implementations).",
    "Core language: Python (data processing, experiment orchestration, statistical gap-localization module).",
    "Graph representation: in-memory graph structure (e.g., NetworkX) — sufficient at project scale, no graph database required.",
    "Experiment/version control: Git, fixed-seed config-driven experiment runner.",
  ], 48, 92, 864, 265, { fontSize: 17.5, spaceAfterPoints: 7 });
  sectionBlock(slide, "Reason for Tool Selection:", [
    "PIDSMaker avoids reimplementing published detectors from scratch, which is infeasible for two students in one semester.",
    "Python matches the team's existing software-engineering strength and has mature statistics/graph libraries, avoiding unnecessary ML framework complexity for the gap-localization module, which is statistical by design.",
  ], 48, 370, 864, 180, { fontSize: 17.2, spaceAfterPoints: 6 });
  sectionBlock(slide, "Advantages and Relevance to the Project:", [
    "Keeps reused components reused (properly cited) and original effort concentrated on the actual contribution — the loss-injection harness and gap-localization module.",
  ], 48, 565, 864, 90, { fontSize: 17.5, spaceAfterPoints: 6 });
}

// 6. Architecture
{
  const slide = contentSlide("6. System Design and Architecture (CO4)", 9, { titleSize: 27 });
  addTextbox(slide, "System Architecture Diagram:", { left: 48, top: 92, width: 864, height: 28 }, { fontSize: 18, bold: true });
  const y = 180;
  const boxes = [
    ["Telemetry\n(dataset)", 38, y, 90, 64],
    ["Normalization", 146, y, 100, 64],
    ["Detection +\nCorrelation/\nChain-building\n(reused methodology)", 264, y - 18, 140, 100],
    ["Loss-Injection\nHarness\n(offline, eval-only)", 422, y - 8, 130, 84],
    ["Ablation\nManifest", 570, y, 95, 64],
    ["Gap-Localization\n(original contribution)", 683, y - 8, 130, 84],
    ["Evidence/\nInvestigation\nView", 831, y - 8, 95, 84],
  ];
  boxes.forEach(([text, left, top, width, height]) => addFlowBox(slide, text, left, top, width, height, { fontSize: width < 80 ? 10.5 : 12.5 }));
  for (let i = 0; i < boxes.length - 1; i++) {
    const [, left, top, width, height] = boxes[i];
    const [, nLeft, nTop, , nHeight] = boxes[i + 1];
    addArrow(slide, left + width + 4, top + height / 2, nLeft - 5, nTop + nHeight / 2);
  }
}

{
  const slide = contentSlide("6. System Design and Architecture (CO4)", 10, { titleSize: 27 });
  sectionBlock(slide, "Data Flow Diagrams:", [
    "Raw records → typed Events/Entities → scored chains → ablated chains (manifest held separately) → gap objects → rendered evidence output.",
  ], 48, 120, 864, 150, { fontSize: 21, spaceAfterPoints: 8 });
  sectionBlock(slide, "Database Design:", [
    "Not applicable in the traditional RDBMS sense — project uses a file/graph-based data model (events, entities, chains as structured objects) rather than a relational database, since the dataset and scale don't warrant one.",
  ], 48, 330, 864, 190, { fontSize: 21, spaceAfterPoints: 8 });
}

// 7. Appropriateness
{
  const slide = contentSlide("7. Appropriateness of Design (CO4)", 11, { titleSize: 28 });
  sectionBlock(slide, "Design Principles Applied:", [
    "Separation of concerns: detection/correlation, loss-injection, and gap-localization are independent, swappable components.",
    "Strict data isolation: the ablation manifest is never exposed to detection or gap-localization — prevents evaluation leakage.",
  ], 48, 92, 864, 165, { fontSize: 18.5, spaceAfterPoints: 8 });
  sectionBlock(slide, "Modularity, Scalability, and Maintainability:", [
    "Modular monolith, not microservices — justified by project scale; avoids operational overhead with no corresponding benefit.",
    "Each pipeline stage is independently testable and independently replaceable (e.g., swapping the reused detector without touching gap-localization).",
  ], 48, 285, 864, 170, { fontSize: 18.5, spaceAfterPoints: 8 });
  sectionBlock(slide, "Design Validation and Review:", [
    "Validated against the research questions directly: each component maps to a specific RQ or to infrastructure that supports it, with nothing added purely for appearance (no auth, no dashboards, no multi-tenancy).",
  ], 48, 485, 864, 130, { fontSize: 18.5, spaceAfterPoints: 8 });
}

// 8. Synchronization
{
  const slide = contentSlide("8. Synchronization of Functionality with Design (CO4, CO5)", 12, { titleSize: 24 });
  addTextbox(slide, "Mapping of Functional Requirements to Design Components:", { left: 48, top: 100, width: 864, height: 28 }, { fontSize: 18, bold: true });
  addTable(slide, [
    ["FR1", "Normalization"],
    ["FR2", "Detection"],
    ["FR3", "Correlation/Chain-building"],
    ["FR4", "Loss-Injection Harness"],
    ["FR5", "Gap-Localization"],
    ["FR6", "Evidence/Investigation View"],
  ], 160, 148, 640, 365, { fontSize: 19, columnTracks: [{ mode: "fixed", value: 110 }, { mode: "fr", value: 1 }] });
}

{
  const slide = contentSlide("8. Synchronization of Functionality with Design (CO4, CO5)", 13, { titleSize: 24 });
  sectionBlock(slide, "Integration and Testing:", [
    "Each component unit-tested against hand-verified samples before pipeline integration.",
    "Full pipeline integration tested end-to-end on a small data slice before scaling to the full experimental matrix.",
  ], 48, 130, 864, 205, { fontSize: 21, spaceAfterPoints: 9 });
  sectionBlock(slide, "Traceability Matrix:", [
    "Every functional requirement (FR1–FR6) traces to exactly one architectural component and at least one research question (RQ1 or RQ2) — no orphan requirements, no unimplemented components.",
  ], 48, 390, 864, 180, { fontSize: 21, spaceAfterPoints: 9 });
}

// 9 and 10 placeholders
{
  const slide = contentSlide("9. Implementation Overview (CO-aligned)", 14, { titleSize: 28 });
  addTextbox(slide, "Content pending — to be added in next revision.", { left: 130, top: 315, width: 700, height: 70 }, {
    fontSize: 26,
    align: "center",
  });
}

{
  const slide = contentSlide("10. Results and Discussion", 15, { titleSize: 30 });
  addTextbox(slide, "Content pending — to be added in next revision.", { left: 130, top: 315, width: 700, height: 70 }, {
    fontSize: 26,
    align: "center",
  });
}

// 11. Conclusion
{
  const slide = contentSlide("11. Conclusion and Future Work", 16, { titleSize: 30 });
  sectionBlock(slide, "Summary of Work Done:", [
    "[PLACEHOLDER — to be finalized once Sections 9/10 content is confirmed] Literature gap established (Evaluation 0); architecture, data model, and experimental methodology fully specified; dataset and tooling selected and justified.",
  ], 48, 90, 864, 120, { fontSize: 17.5, spaceAfterPoints: 6 });
  sectionBlock(slide, "Limitations:", [
    "Gap-localization method is statistical, not learned — trades some potential accuracy for interpretability and feasibility given limited ML background and scarce labelled attack data.",
    "Evaluation confined to one OS/telemetry family and a public benchmark dataset with known data-quality quirks (documented, not silently corrected).",
    "Robustness to adversarial telemetry suppression (attacker actively blinding sensors) is motivation, not a solved problem — out of scope.",
  ], 48, 225, 864, 245, { fontSize: 17.2, spaceAfterPoints: 6 });
  sectionBlock(slide, "Future Enhancements:", [
    "Extend gap-localization with a learned (e.g., link-prediction) component once the statistical baseline is validated (RQ3, stretch).",
    "Extend to a second loss mechanism (attacker-targeted removal) or a second OS family.",
    "Human-subject evaluation of evidence-view usefulness, if ethics approval becomes feasible.",
  ], 48, 490, 864, 155, { fontSize: 17.2, spaceAfterPoints: 6 });
}

// 13. References
{
  const slide = contentSlide("13. References", 17, { titleSize: 32 });
  const refs = [
    '[1] X. Han, T. Pasquier, A. Bates, J. Mickens, and M. Seltzer, "UNICORN: Runtime Provenance-Based Detector for Advanced Persistent Threats," in Proc. Network and Distributed System Security Symposium (NDSS), 2020.',
    '[2] X. Han, T. Pasquier, and M. Seltzer, "Provenance-based intrusion detection: Opportunities and challenges," in Proc. 10th USENIX Workshop on the Theory and Practice of Provenance (TaPP), 2018.',
    '[3] E. Manzoor, S. M. Milajerdi, and L. Akoglu, "Fast Memory-Efficient Anomaly Detection in Streaming Heterogeneous Graphs," in Proc. 22nd ACM SIGKDD Int. Conf. Knowledge Discovery and Data Mining (KDD), 2016, pp. 1035-1044.',
    '[5] Z. Cheng, Q. Lv, J. Liang, Y. Wang, D. Sun, T. Pasquier, and X. Han, "Kairos: Practical Intrusion Detection and Investigation Using Whole-System Provenance," in Proc. 2024 IEEE Symposium on Security and Privacy (S&P), 2024.',
  ];
  const body = slide.shapes.add({
    geometry: "textbox",
    position: { left: 56, top: 115, width: 850, height: 510 },
    fill: "none",
    line: { fill: "none", width: 0 },
  });
  body.text = refs.join("\n\n");
  body.text.style = {
    typeface: fonts.body,
    fontSize: 17.2,
    color: "#000000",
    autoFit: "none",
  };
}

// 14. Q&A
{
  const slide = contentSlide("14. Q&A / Thank You", 18, { titleSize: 34 });
  addTextbox(slide, "Jaffar Jned\nMahmoud Bakir", { left: 250, top: 190, width: 460, height: 110 }, {
    fontSize: 30,
    bold: true,
    align: "center",
  });
  addTextbox(slide, '"Reasoning about what your security telemetry isn\'t telling you."', { left: 120, top: 335, width: 720, height: 70 }, {
    fontSize: 24,
    italic: true,
    align: "center",
  });
  addTextbox(slide, "Contact/repo link (if applicable).", { left: 250, top: 455, width: 460, height: 50 }, {
    fontSize: 22,
    align: "center",
  });
}

const templateSha256 = crypto.createHash("sha256").update(await fs.readFile(sourceTemplatePath)).digest("hex");
const candidatePath = path.join(workspaceDir, ".codex-finalizer", "candidate-eval3.pptx");
await fs.mkdir(path.dirname(candidatePath), { recursive: true });
await (await PresentationFile.exportPptx(presentation)).save(candidatePath);

const requirements = {
  explicitTotalSlideCount: 18,
  requiredNativeTableOwnerSlides: [5, 12],
  requiredNativeChartOwnerSlides: [],
};

const fontPolicy = {
  basis: "reference",
  families: [fonts.title, fonts.body],
  referencePath: sourceTemplatePath,
  referenceSha256: templateSha256,
};

await finalizePresentation({
  ...requirements,
  workspaceDir,
  candidatePath,
  finalPath: FINAL_PPTX,
  pythonExecutable: RUNTIME_PYTHON,
  integrityValidatorPath: path.join(SKILL_DIR, "container_tools/inspect_presentation_package_integrity.py"),
  layoutValidatorPath: path.join(SKILL_DIR, "container_tools/inspect_presentation_layout_geometry.py"),
  layoutArgs: [
    "--expected-slide-size-emu",
    "9144000,6858000",
    "--validate-bullet-geometry",
    "--validate-heading-fit",
    "--require-native-table-slide",
    "5",
    "--require-native-table-slide",
    "12",
  ],
  requiredNativeTableOwnerSlides: requirements.requiredNativeTableOwnerSlides,
  fontPolicy,
  verifyArtifactToolImport: true,
  receiptPath: path.join(workspaceDir, ".codex-finalizer", "Eval-3_Final_Project_Evaluation_Cybersecurity_v2.validation.json"),
});

const finalPresentation = await PresentationFile.importPptx(await (await import(pathToFileURL(path.join(runtimeModules, "@oai/artifact-tool/dist/artifact_tool.mjs")).href)).FileBlob.load(FINAL_PPTX));
for (let i = 0; i < finalPresentation.slides.items.length; i++) {
  const png = await finalPresentation.slides.items[i].export({ format: "png", scale: 1 });
  await fs.writeFile(path.join(TMP_DIR, `final-slide-${String(i + 1).padStart(2, "0")}.png`), new Uint8Array(await png.arrayBuffer()));
}
await fs.writeFile(path.join(TMP_DIR, "final-path.txt"), FINAL_PPTX, "utf8");
