/* QSentinal front-end interactions.
   PQC operations are represented as educational simulations unless explicitly
   noted. File encryption uses the browser Web Crypto AES-GCM API only. */
(() => {
  "use strict";
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const toast = (message) => {
    const el = $("#toast");
    if (!el) return;
    el.textContent = message;
    el.classList.add("show");
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => el.classList.remove("show"), 2600);
  };
  const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  // Mobile navigation
  const navToggle = $("#navToggle");
  const navLinks = $("#navLinks");
  navToggle?.addEventListener("click", () => {
    const open = navLinks.classList.toggle("open");
    navToggle.setAttribute("aria-expanded", String(open));
  });
  $$("#navLinks a").forEach(link => link.addEventListener("click", () => {
    navLinks.classList.remove("open");
    navToggle?.setAttribute("aria-expanded", "false");
  }));

  // Scroll reveal (kept subtle; content remains visible if observer is unavailable)
  if ("IntersectionObserver" in window && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add("in-view");
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.08 });
    $$(".info-card,.mini-stat,.algorithm-card,.learning-card,.comparison-card").forEach(el => {
      el.classList.add("reveal");
      observer.observe(el);
    });
  }

  // Charts
  let riskChart, benchmarkChart;
  const chartDefaults = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { backgroundColor: "#171d37", padding: 10, titleFont: { family: "DM Sans" }, bodyFont: { family: "DM Sans" } } },
    scales: {
      x: { grid: { display: false }, ticks: { color: "#969db1", font: { size: 9, family: "DM Sans" } }, border: { display: false } },
      y: { grid: { color: "#eef0f6" }, ticks: { color: "#969db1", font: { size: 9, family: "DM Sans" } }, border: { display: false } }
    }
  };
  function initRiskChart() {
    const canvas = $("#riskChart");
    if (!canvas || !window.Chart) return;
    riskChart = new Chart(canvas, {
      type: "line",
      data: { labels: ["2026", "2028", "2030", "2032", "2034", "2036"], datasets: [{ data: [38, 45, 53, 62, 72, 82], borderColor: "#7a70e6", backgroundColor: "rgba(122,112,230,.10)", fill: true, tension: .38, pointRadius: 3, pointBackgroundColor: "#7a70e6", borderWidth: 2 }] },
      options: { ...chartDefaults, scales: { ...chartDefaults.scales, y: { ...chartDefaults.scales.y, min: 0, max: 100, ticks: { ...chartDefaults.scales.y.ticks, stepSize: 25 } } } }
    });
  }
  const benchmarkData = {
    key: { label: "Public key size (bytes)", values: [256, 64, 1184, 1952], max: 2200 },
    signature: { label: "Signature / ciphertext size (bytes)", values: [256, 64, 1088, 3309], max: 3600 },
    speed: { label: "Illustrative relative latency (index)", values: [48, 22, 31, 43], max: 55 }
  };
  function initBenchmarkChart(metric = "key") {
    const canvas = $("#benchmarkChart");
    if (!canvas || !window.Chart) return;
    const item = benchmarkData[metric];
    if (benchmarkChart) benchmarkChart.destroy();
    benchmarkChart = new Chart(canvas, {
      type: "bar",
      data: { labels: ["RSA-2048", "ECC P-256", "ML-KEM-768", "ML-DSA-65"], datasets: [{ data: item.values, backgroundColor: ["#b9bfdf", "#c9cdec", "#796fe5", "#a18be9"], borderRadius: 7, borderSkipped: false, maxBarThickness: 55 }] },
      options: { ...chartDefaults, indexAxis: "y", plugins: { ...chartDefaults.plugins, tooltip: { ...chartDefaults.plugins.tooltip, callbacks: { label: context => ` ${context.raw.toLocaleString()} ${metric === "speed" ? "index" : "bytes"}` } } }, scales: { x: { ...chartDefaults.scales.x, min: 0, max: item.max, title: { display: true, text: item.label, color: "#9299ad", font: { size: 9 } } }, y: { ...chartDefaults.scales.y, grid: { display: false } } } }
    });
  }
  initRiskChart();
  initBenchmarkChart();
  $$(".metric-tab").forEach(button => button.addEventListener("click", () => {
    $$(".metric-tab").forEach(tab => tab.classList.toggle("active", tab === button));
    initBenchmarkChart(button.dataset.metric);
  }));

  // Readiness score: intentionally illustrative rules, not a security audit.
  const scoreRing = $("#scoreRing");
  function assessRisk() {
    const industry = $("#industrySelect").value;
    const algorithm = $("#algorithmSelect").value;
    const infra = $("#infraSelect").value;
    let score = algorithm === "rsa" ? 72 : algorithm === "ecc" ? 68 : algorithm === "hybrid" ? 43 : 19;
    score += ({ banking: 9, healthcare: 10, government: 8, cloud: 5, enterprise: 4, iot: 7 })[industry];
    score += ({ hybrid: 0, onprem: 4, cloud: -2, iot: 8 })[infra];
    score = Math.max(8, Math.min(96, score));
    const level = score >= 65 ? "Elevated exposure" : score >= 38 ? "Moderate exposure" : "Lower exposure";
    const className = score >= 65 ? "high" : score >= 38 ? "medium" : "low";
    $("#riskScore").textContent = score;
    $("#riskStatus").textContent = level;
    $("#riskStatus").className = `risk-status ${className}`;
    $("#readinessLabel").textContent = `${100 - score} / 100`;
    $("#riskSummary").textContent = score >= 65
      ? "Legacy public-key dependencies and long-lived sensitive data may increase future exposure."
      : score >= 38
        ? "Some migration foundations may exist, but dependencies and long-lived data need validation."
        : "Your selected profile indicates a stronger starting point. Continue validating implementation and coverage.";
    scoreRing.style.background = `conic-gradient(${score >= 65 ? "#e58a80" : score >= 38 ? "#e5b46b" : "#39b990"} 0 ${score}%, #e3e6f5 ${score}% 100%)`;
    $("#rsaExposure").textContent = algorithm === "pqc" ? "Reduced" : algorithm === "ecc" ? "Review" : "High";
    $("#eccExposure").textContent = algorithm === "pqc" ? "Reduced" : algorithm === "rsa" ? "Review" : "High";
    $("#pqcExposure").textContent = algorithm === "pqc" ? "Selected" : algorithm === "hybrid" ? "Partial" : "Not detected";
    $("#recommendTitle").textContent = score >= 65 ? "Start with a cryptographic inventory" : score >= 38 ? "Validate your hybrid transition" : "Test coverage and crypto agility";
    $("#recommendText").textContent = score >= 65
      ? `For ${industry}, map RSA and ECC use, identify long-lived sensitive data, and define a standards-based PQC pilot.`
      : score >= 38
        ? "Confirm where hybrid protection is deployed, test interoperability and document remaining classical dependencies."
        : "Validate algorithm coverage, certificate lifecycle, key management and the ability to update cryptographic components.";
    if (riskChart) {
      riskChart.data.datasets[0].data = [Math.max(10, score - 34), Math.max(12, score - 27), Math.max(18, score - 18), Math.max(25, score - 10), score, Math.min(100, score + 10)];
      riskChart.update();
    }
    toast("Illustrative risk profile updated.");
  }
  $("#assessButton")?.addEventListener("click", assessRisk);

  // Messaging workflow simulation
  const messageInput = $("#messageInput");
  const messageCount = $("#messageCount");
  messageInput?.addEventListener("input", () => messageCount.textContent = `${messageInput.value.length} / 500`);
  $("#runHeroDemo")?.addEventListener("click", () => {
    document.querySelector("#messaging").scrollIntoView({ behavior: "smooth" });
    setTimeout(() => $("#sendMessageButton")?.click(), 550);
  });
  $("#sendMessageButton")?.addEventListener("click", async () => {
    const message = messageInput.value.trim();
    if (!message) return toast("Enter a message before running the demo.");
    const button = $("#sendMessageButton");
    button.disabled = true;
    $("#messageDetails").hidden = true;
    const nodes = $$(".workflow-node");
    nodes.forEach(n => n.classList.remove("active", "done"));
    $("#workflowState").textContent = "PROCESSING";
    const stages = [
      ["Generating recipient key pair…", "Key establishment", "ML-KEM workflow represented"],
      ["Establishing a shared secret…", "Shared secret established", "Both parties derive matching session material (concept)"],
      ["Protecting message content…", "Encryption stage complete", "AES-GCM is shown as the symmetric data-protection layer"],
      ["Bob receives and recovers the message…", "Secure workflow complete", "Message recovery is represented in this UI simulation"]
    ];
    for (let i = 0; i < stages.length; i++) {
      nodes[i].classList.add("active");
      $("#workflowResult").innerHTML = `<div class="result-lock">⌁</div><div><b>${stages[i][0]}</b><p>${stages[i][2]}</p></div>`;
      await wait(650);
      nodes[i].classList.remove("active");
      nodes[i].classList.add("done");
    }
    $("#workflowState").textContent = "DEMO COMPLETE";
    $("#workflowResult").innerHTML = `<div class="result-lock">✓</div><div><b>${stages[3][1]}</b><p>Illustrative workflow completed. No ML-KEM operation was executed.</p></div>`;
    $("#cipherPreview").textContent = btoa(unescape(encodeURIComponent(message))).slice(0, 110) + (message.length > 80 ? "…" : "");
    $("#messageDetails").hidden = false;
    button.disabled = false;
    toast("Secure messaging workflow demo completed.");
  });

  // ML-KEM educational stepper
  const kemSteps = [
    { label: "STEP 01 / KEY GENERATION", title: "Create a key pair", text: "The recipient generates a public key and a private key. The public key can be shared; the private key remains protected by the recipient.", output: "Public key + private key pair" },
    { label: "STEP 02 / ENCAPSULATION", title: "Create shared secret material", text: "A sender uses the recipient's public key to encapsulate a shared secret, producing an encapsulation ciphertext and matching secret material.", output: "Encapsulation ciphertext + shared secret" },
    { label: "STEP 03 / DECAPSULATION", title: "Recover the same shared secret", text: "The recipient uses the private key and ciphertext to decapsulate and derive the same shared secret. The secret can then feed a symmetric key-derivation process.", output: "Matching shared secret at both endpoints" }
  ];
  let kemIndex = 0;
  function renderKem() {
    const step = kemSteps[kemIndex];
    $("#kemStepLabel").textContent = step.label;
    $("#kemStepTitle").textContent = step.title;
    $("#kemStepText").textContent = step.text;
    $("#kemOutput").querySelector("b").textContent = step.output;
    $$(".lab-step").forEach((el, index) => el.classList.toggle("active", index === kemIndex));
    $("#nextKemStep").innerHTML = kemIndex === 2 ? "Restart walkthrough ↻" : "Next step →";
  }
  $$(".lab-step").forEach((el, index) => el.addEventListener("click", () => { kemIndex = index; renderKem(); }));
  $("#nextKemStep")?.addEventListener("click", () => { kemIndex = (kemIndex + 1) % 3; renderKem(); });
  $("#resetKem")?.addEventListener("click", () => { kemIndex = 0; renderKem(); });
  renderKem();

  // ML-DSA concept demonstration: no signature is generated.
  $("#signButton")?.addEventListener("click", async () => {
    const text = $("#documentInput").value.trim();
    if (!text) return toast("Enter document text first.");
    const btn = $("#signButton");
    btn.disabled = true;
    $("#signatureOutput").classList.remove("verified");
    $("#signatureOutput").innerHTML = `<div class="signature-seal">…</div><div><b>Creating conceptual signature…</b><small>Preparing the verification walkthrough</small></div>`;
    await wait(850);
    $("#signatureOutput").classList.add("verified");
    $("#signatureOutput").innerHTML = `<div class="signature-seal">✓</div><div><b>Verification concept successful</b><small>Authenticity and integrity status shown for demonstration.</small></div>`;
    $("#signatureStatus").textContent = "Demo verified";
    btn.disabled = false;
    toast("ML-DSA signature workflow simulated.");
  });

  // Local file encryption using Web Crypto AES-GCM.
  let selectedFile = null;
  const fileInput = $("#fileInput");
  const dropZone = $("#dropZone");
  function setFile(file) {
    if (!file) return;
    const allowed = /\.(pdf|docx|txt|png|jpe?g)$/i.test(file.name);
    if (!allowed) { toast("Choose a PDF, DOCX, TXT, PNG or JPG file."); return; }
    selectedFile = file;
    $("#selectedFile").hidden = false;
    $("#selectedFile").textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
    $("#protectFileButton").disabled = false;
    $("#vaultResult").textContent = "File selected locally. Choose a mode and start the demo.";
  }
  $("#browseFiles")?.addEventListener("click", () => fileInput.click());
  fileInput?.addEventListener("change", () => setFile(fileInput.files[0]));
  ["dragenter", "dragover"].forEach(type => dropZone?.addEventListener(type, event => { event.preventDefault(); dropZone.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach(type => dropZone?.addEventListener(type, event => { event.preventDefault(); dropZone.classList.remove("dragging"); }));
  dropZone?.addEventListener("drop", event => setFile(event.dataTransfer.files[0]));
  $("#protectFileButton")?.addEventListener("click", async () => {
    if (!selectedFile) return;
    const result = $("#vaultResult");
    const button = $("#protectFileButton");
    const mode = $('input[name="vaultMode"]:checked').value;
    if (!window.crypto?.subtle) {
      result.textContent = "Web Crypto is unavailable. Open this page on HTTPS or localhost to use local AES-GCM encryption.";
      return;
    }
    button.disabled = true;
    result.textContent = "Encrypting file locally…";
    try {
      const bytes = await selectedFile.arrayBuffer();
      const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
      const rawKey = await crypto.subtle.exportKey("raw", key);
      const blob = new Blob([iv, encrypted], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${selectedFile.name}.qsentinal.enc`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1500);
      result.textContent = `Encrypted locally with AES-256-GCM. Download started. ${mode === "hybrid" ? "ML-KEM hybrid key establishment is a conceptual label only. " : ""}Demo key material is not persisted; save a real key-management workflow before production use.`;
      // Deliberately do not expose or persist the generated key. This is a UI demonstration.
      new Uint8Array(rawKey).fill(0);
      toast("Encrypted file download created.");
    } catch (error) {
      console.error(error);
      result.textContent = "Encryption failed in this browser. Try a smaller file or a modern browser on HTTPS.";
    } finally {
      button.disabled = false;
    }
  });

  // Migration roadmap customization
  $("#generateRoadmap")?.addEventListener("click", () => {
    const sector = $("#sectorSelect").value;
    const priority = $("#prioritySelect").value;
    $("#roadmapTitle").textContent = `${sector} quantum transition blueprint`;
    const firstDescription = {
      "Confidentiality longevity": "Prioritize data with long confidentiality lifetimes, stored archives, backups and external data flows.",
      "Authentication": "Inventory certificates, code-signing, identity, firmware signing and all signature verification paths.",
      "Device lifecycle": "Map device longevity, firmware update mechanisms, constrained hardware and supplier dependencies.",
      "Compliance": "Map applicable standards, contractual obligations, system owners and evidence needed for governance."
    }[priority];
    const descriptions = [
      firstDescription,
      `Assess ${sector.toLowerCase()} data sensitivity, cryptographic exposure and the operational impact of vulnerable dependencies.`,
      "Run a controlled hybrid pilot; validate interoperability, performance, key management, observability and rollback.",
      "Migrate prioritized key-establishment and signature use cases to approved PQC implementations in planned waves.",
      "Continuously monitor cryptographic assets, implementation updates, supplier readiness and emerging standards."
    ];
    $$("#roadmapList .roadmap-item p").forEach((p, index) => p.textContent = descriptions[index]);
    toast(`${sector} roadmap updated for ${priority.toLowerCase()}.`);
  });

  // Curated advisor responses — clearly not a live AI integration.
  const answerFor = (prompt) => {
    const q = prompt.toLowerCase();
    if (q.includes("ml-kem")) return "ML-KEM is a key-encapsulation mechanism standardized in FIPS 203. In simple terms, it lets two parties establish shared secret material over a public channel. That secret is typically used with a symmetric algorithm such as AES-GCM to protect data. ML-KEM does not directly encrypt arbitrary files.";
    if (q.includes("ml-dsa")) return "ML-DSA is a post-quantum digital signature scheme standardized in FIPS 204. A signer uses a private key to create a signature; a recipient uses the corresponding public key to verify authenticity and integrity. It is a migration candidate for signature systems such as RSA signatures and ECDSA.";
    if (q.includes("shor") || q.includes("rsa") || q.includes("ecc")) return "Shor's algorithm is a quantum algorithm for factoring integers and computing discrete logarithms. If run at scale on a sufficiently capable fault-tolerant quantum computer, it would threaten RSA and elliptic-curve cryptography. Current quantum computers are not capable of doing this to real-world key sizes.";
    if (q.includes("migrat") || q.includes("first") || q.includes("priorit")) return "Start with a cryptographic inventory: identify where public-key algorithms, certificates, keys and protocols are used. Prioritize systems protecting long-lived sensitive data, high-impact identity/signature workflows, hard-to-update devices and external dependencies. Then pilot standards-based PQC and test interoperability before phased rollout.";
    if (q.includes("harvest") || q.includes("decrypt")) return "Harvest Now, Decrypt Later describes an attacker collecting encrypted data today with the hope of decrypting it in the future. It matters most when information must remain confidential for a long time. Inventory data lifetimes and plan a transition for vulnerable key-establishment mechanisms.";
    if (q.includes("hybrid")) return "A hybrid approach combines a classical mechanism with a post-quantum mechanism during a transition. The goal is to maintain compatibility while adding a PQC security contribution. It must be designed and implemented carefully, with standards-aligned protocols, sound key derivation and testing.";
    return "A useful first step is to identify the cryptographic assets involved, the data they protect, and how long that data needs protection. QSentinal's readiness snapshot and migration roadmap can help structure that discovery. For implementation decisions, validate against current NIST standards and specialist security guidance.";
  };
  function addChatMessage(text, who) {
    const row = document.createElement("div");
    row.className = `chat-message ${who}`;
    const avatar = document.createElement("span");
    avatar.className = "chat-avatar";
    avatar.textContent = who === "user" ? "Y" : "Q";
    const bubble = document.createElement("p");
    bubble.textContent = text;
    row.append(avatar, bubble);
    $("#chatMessages").append(row);
    $("#chatMessages").scrollTop = $("#chatMessages").scrollHeight;
  }
  function askAdvisor(prompt) {
    if (!prompt.trim()) return;
    addChatMessage(prompt, "user");
    const response = answerFor(prompt);
    setTimeout(() => addChatMessage(response, "assistant"), 300);
  }
  $("#chatForm")?.addEventListener("submit", event => {
    event.preventDefault();
    const input = $("#chatInput");
    askAdvisor(input.value);
    input.value = "";
  });
  $$(".topic-chip").forEach(button => button.addEventListener("click", () => askAdvisor(button.dataset.prompt)));

  // Hero and button feedback
  $("#runHeroDemo")?.addEventListener("keydown", event => { if (event.key === "Enter") $("#sendMessageButton").click(); });
})();
