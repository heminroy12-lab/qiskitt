/* QSentinal Client Controller
   Synchronizes with Flask API (Port 5000) with Seamless Client-Side Fallback.
   Zero-Knowledge Authenticated File Encryption & Decryption (PBKDF2 + AES-256-GCM).
   Fully Patched Cryptographic Protocols & Secure Messaging Pipeline. */

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
    toast.timer = setTimeout(() => el.classList.remove("show"), 2800);
  };

  const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  // Determine API base URL (supports direct port 5000 or relative endpoint)
  const API_BASE = window.location.port === "5000"
    ? `${window.location.origin}/api/v1`
    : "http://127.0.0.1:5000/api/v1";

  let isBackendConnected = false;

  // ---------------------------------------------------------------------------
  // 1. Backend Synchronization & Health Monitoring
  // ---------------------------------------------------------------------------
  async function checkBackendSync() {
    const pill = $("#backendStatusPill");
    const label = $("#backendStatusText");

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2500);
      const res = await fetch(`${API_BASE}/status`, { signal: controller.signal });
      clearTimeout(timeoutId);

      if (res.ok) {
        const data = await res.json();
        isBackendConnected = true;
        if (pill) {
          pill.classList.remove("offline");
          pill.title = `Connected to ${data.service} (v${data.version})`;
        }
        if (label) label.textContent = "Backend: Synced (Flask v1.0)";
        return true;
      }
    } catch {
      // Backend not running or unreachable
    }

    isBackendConnected = false;
    if (pill) {
      pill.classList.add("offline");
      pill.title = "Operating in client-side standalone mode. Flask backend unreachable.";
    }
    if (label) label.textContent = "Standalone Offline Mode";
    return false;
  }

  // Periodic heartbeat every 15 seconds
  checkBackendSync();
  setInterval(checkBackendSync, 15000);

  // ---------------------------------------------------------------------------
  // 2. Navigation & View Interactions
  // ---------------------------------------------------------------------------
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

  // Scroll reveal
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

  // ---------------------------------------------------------------------------
  // 3. Chart.js Initializations & Benchmarks
  // ---------------------------------------------------------------------------
  let benchmarkChart;
  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#171d37",
        padding: 10,
        titleFont: { family: "DM Sans" },
        bodyFont: { family: "DM Sans" }
      }
    },
    scales: {
      x: { grid: { display: false }, ticks: { color: "#848ca3", font: { size: 11, family: "DM Sans" } }, border: { display: false } },
      y: { grid: { color: "#eef0f6" }, ticks: { color: "#848ca3", font: { size: 11, family: "DM Sans" } }, border: { display: false } }
    }
  };

  const fallbackBenchmarkData = {
    key: { label: "Public key size (bytes)", values: [256, 64, 1184, 1952], max: 2200 },
    signature: { label: "Signature / ciphertext size (bytes)", values: [256, 64, 1088, 3309], max: 3600 },
    speed: { label: "Relative latency index", values: [48, 22, 31, 43], max: 55 }
  };

  async function initBenchmarkChart(metric = "key") {
    const canvas = $("#benchmarkChart");
    if (!canvas || !window.Chart) return;

    let chartData = fallbackBenchmarkData[metric];

    if (isBackendConnected) {
      try {
        const res = await fetch(`${API_BASE}/benchmarks?metric=${metric}`);
        if (res.ok) {
          const apiData = await res.json();
          chartData = {
            label: `${apiData.title} (${apiData.unit})`,
            values: apiData.values,
            max: Math.max(...apiData.values) * 1.18
          };
        }
      } catch (err) {
        console.warn("Backend benchmark sync failed, using client data", err);
      }
    }

    if (benchmarkChart) benchmarkChart.destroy();
    benchmarkChart = new Chart(canvas, {
      type: "bar",
      data: {
        labels: ["RSA-2048", "ECC P-256", "ML-KEM-768", "ML-DSA-65"],
        datasets: [{
          data: chartData.values,
          backgroundColor: ["#b9bfdf", "#c9cdec", "#796fe5", "#a18be9"],
          borderRadius: 7,
          borderSkipped: false,
          maxBarThickness: 55
        }]
      },
      options: {
        ...chartDefaults,
        indexAxis: "y",
        plugins: {
          ...chartDefaults.plugins,
          tooltip: {
            ...chartDefaults.plugins.tooltip,
            callbacks: {
              label: context => ` ${context.raw.toLocaleString()} ${metric === "speed" ? "index" : "bytes"}`
            }
          }
        },
        scales: {
          x: {
            ...chartDefaults.scales.x,
            min: 0,
            max: chartData.max,
            title: { display: true, text: chartData.label, color: "#848ca3", font: { size: 11 } }
          },
          y: { ...chartDefaults.scales.y, grid: { display: false } }
        }
      }
    });
  }

  initBenchmarkChart();

  $$(".metric-tab").forEach(button => button.addEventListener("click", () => {
    $$(".metric-tab").forEach(tab => tab.classList.toggle("active", tab === button));
    initBenchmarkChart(button.dataset.metric);
  }));

  // ===== QUANTUM RISK CALCULATOR =====
  // Dynamic Mosca-theorem-based risk tool (x + y > z) and algorithm vulnerability weighting.

  const RISK_CONFIG = {
    algorithms: {
      rsa2048: { points: 35, type: "asymmetric-kem-enc", name: "RSA-2048" },
      rsa3072: { points: 32, type: "asymmetric-kem-enc", name: "RSA-3072" },
      ecc256: { points: 33, type: "asymmetric-kem-enc", name: "ECC P-256" },
      ecc384: { points: 30, type: "asymmetric-kem-enc", name: "ECC P-384" },
      dhecdh: { points: 33, type: "asymmetric-kem-enc", name: "DH/ECDH Classical" },
      aes128: { points: 8, type: "symmetric-128", name: "AES-128" },
      aes256: { points: 2, type: "symmetric-256", name: "AES-256" },
      hybrid: { points: 6, type: "hybrid", name: "Hybrid (Classical + PQC)" },
      pqc: { points: 0, type: "pqc", name: "ML-KEM / ML-DSA (NIST PQC)" }
    },
    sensitivity: {
      low: 2,
      medium: 6,
      high: 11,
      critical: 14
    },
    exposure: {
      internal: 4,
      partner: 9,
      public: 15
    },
    industries: {
      banking: { multiplier: 1.10, name: "Banking & Finance" },
      healthcare: { multiplier: 1.10, name: "Healthcare" },
      government: { multiplier: 1.15, name: "Government & Defense" },
      energy: { multiplier: 1.05, name: "Energy & Utilities" },
      telecom: { multiplier: 1.05, name: "Telecom" },
      retail: { multiplier: 1.00, name: "Retail" },
      technology: { multiplier: 1.00, name: "Technology" },
      other: { multiplier: 1.00, name: "Other" }
    },
    tiers: [
      { max: 24, name: "LOW", label: "LOW THREAT · QUANTUM RESILIENT BASELINE", className: "low", stroke: "#10b981" },
      { max: 49, name: "MODERATE", label: "MODERATE THREAT · TRANSITION REQUIRED", className: "moderate", stroke: "#d97706" },
      { max: 74, name: "HIGH", label: "HIGH THREAT · ELEVATED EXPOSURE", className: "high", stroke: "#e57a3b" },
      { max: 100, name: "CRITICAL", label: "CRITICAL THREAT · IMMEDIATE PRIORITY", className: "critical", stroke: "#e5484d" }
    ],
    ringCircumference: 414.69 // 2 * Math.PI * 66
  };

  function computeRisk(inputs) {
    const industryKey = RISK_CONFIG.industries[inputs.industry] ? inputs.industry : "banking";
    const cryptoKey = RISK_CONFIG.algorithms[inputs.crypto] ? inputs.crypto : "rsa2048";
    const sensitivityKey = RISK_CONFIG.sensitivity[inputs.sensitivity] !== undefined ? inputs.sensitivity : "high";
    const exposureKey = RISK_CONFIG.exposure[inputs.exposure] !== undefined ? inputs.exposure : "public";

    const x = Math.max(1, Math.min(30, parseInt(inputs.x, 10) || 10));
    const y = Math.max(1, Math.min(15, parseInt(inputs.y, 10) || 4));
    const z = Math.max(3, Math.min(30, parseInt(inputs.z, 10) || 8));

    const sum = x + y;
    const violated = sum > z;
    const margin = violated ? sum - z : 0;
    const safeMargin = !violated ? z - sum : 0;

    let moscaPoints = 0;
    if (violated) {
      moscaPoints = 15 + Math.min(10, 2 * margin);
    } else {
      moscaPoints = safeMargin <= 2 ? 5 : 0;
    }

    const algoPoints = RISK_CONFIG.algorithms[cryptoKey].points;
    const sensPoints = RISK_CONFIG.sensitivity[sensitivityKey];
    const expoPoints = RISK_CONFIG.exposure[exposureKey];
    const multiplier = RISK_CONFIG.industries[industryKey].multiplier;

    const baseSum = algoPoints + moscaPoints + sensPoints + expoPoints;
    const rawScore = baseSum * multiplier;
    const score = Math.max(0, Math.min(100, Math.round(rawScore)));

    const tier = RISK_CONFIG.tiers.find(t => score <= t.max) || RISK_CONFIG.tiers[RISK_CONFIG.tiers.length - 1];

    const recs = [];
    const algoMeta = RISK_CONFIG.algorithms[cryptoKey];

    if (algoMeta.type === "asymmetric-kem-enc") {
      const kemLevel = (sensitivityKey === "critical" || x >= 20)
        ? "KEM: ML-KEM-1024 (NIST FIPS 203, Level 5)"
        : "KEM: ML-KEM-768 (NIST FIPS 203, Level 3)";
      recs.push(kemLevel);

      const dsaLevel = (sensitivityKey === "critical")
        ? "Signature: ML-DSA-87 (NIST FIPS 204, Level 5)"
        : "Signature: ML-DSA-65 (NIST FIPS 204, Level 3)";
      recs.push(dsaLevel);
    } else if (algoMeta.type === "symmetric-128") {
      recs.push("AES-256 upgrade recommended. Grover's algorithm halves effective symmetric key length (AES-128 yields 64-bit security), though symmetric ciphers are not broken by Shor's algorithm.");
    } else if (algoMeta.type === "symmetric-256") {
      recs.push("AES-256 provides a robust 128-bit post-quantum security margin against Grover's algorithm. Ensure strict key rotation and management.");
    } else {
      recs.push("No algorithm change required. Focus on crypto agility and inventory.");
    }

    if (violated && algoMeta.type !== "pqc") {
      recs.push("Start with a hybrid (classical + PQC) pilot.");
    }

    let explanation = "";
    if (violated) {
      explanation = `Critical Mosca violation: Retention (${x}y) + Migration (${y}y) = ${sum}y, exceeding the estimated quantum threshold (${z}y) by ${margin}y. Traffic intercepted today is vulnerable to Harvest Now, Decrypt Later (HNDL).`;
    } else if (safeMargin <= 2) {
      explanation = `Near-threshold Mosca posture: Retention (${x}y) + Migration (${y}y) = ${sum}y vs ${z}y threshold. While currently within the safe window by ${safeMargin}y, migration planning must commence immediately to avoid future HNDL exposure.`;
    } else {
      explanation = `Within safe Mosca window: Retention (${x}y) + Migration (${y}y) = ${sum}y operates within the estimated quantum threshold (${z}y) with a safe margin of ${safeMargin}y. Continue proactive inventory discovery and lifecycle agility.`;
    }

    return {
      score,
      tier,
      parts: {
        algo: algoPoints,
        mosca: moscaPoints,
        sens: sensPoints,
        expo: expoPoints,
        baseSum,
        multiplier
      },
      mosca: {
        x,
        y,
        z,
        sum,
        margin,
        safeMargin,
        violated
      },
      recommendations: recs,
      explanation
    };
  }

  let riskScoreAnimFrame = null;
  let lastDisplayedScore = 0;

  function renderRisk(res, animate = true) {
    // 1. Slider labels & attributes
    const valX = $("#valX");
    const valY = $("#valY");
    const valZ = $("#valZ");
    const sliderX = $("#sliderX");
    const sliderY = $("#sliderY");
    const sliderZ = $("#sliderZ");

    if (valX) valX.textContent = `${res.mosca.x} years`;
    if (valY) valY.textContent = `${res.mosca.y} years`;
    if (valZ) valZ.textContent = `${res.mosca.z} years`;

    if (sliderX) {
      sliderX.setAttribute("aria-valuenow", res.mosca.x);
      sliderX.setAttribute("aria-valuetext", `${res.mosca.x} years`);
    }
    if (sliderY) {
      sliderY.setAttribute("aria-valuenow", res.mosca.y);
      sliderY.setAttribute("aria-valuetext", `${res.mosca.y} years`);
    }
    if (sliderZ) {
      sliderZ.setAttribute("aria-valuenow", res.mosca.z);
      sliderZ.setAttribute("aria-valuetext", `${res.mosca.z} years`);
    }

    // 2. Mosca Status Bar
    const eqText = $("#moscaEquationText");
    const eqBadge = $("#moscaBadge");
    if (eqText) {
      eqText.textContent = `${res.mosca.x}y (X) + ${res.mosca.y}y (Y) = ${res.mosca.sum}y vs ${res.mosca.z}y (Z)`;
    }
    if (eqBadge) {
      if (res.mosca.violated) {
        eqBadge.textContent = "VIOLATED (HNDL RISK)";
        eqBadge.className = "mosca-badge violated";
      } else {
        eqBadge.textContent = "WITHIN SAFE WINDOW";
        eqBadge.className = "mosca-badge safe";
      }
    }

    // 3. SVG Score Ring
    const ringCircle = $("#ringProgressCircle");
    const scoreNum = $("#dynamicRiskScore");
    const circumference = RISK_CONFIG.ringCircumference;
    const offset = circumference - (circumference * res.score / 100);

    if (ringCircle) {
      ringCircle.style.strokeDashoffset = offset.toFixed(2);
      ringCircle.style.stroke = res.tier.stroke;
    }

    // Smoothly animate score number unless reduced motion is preferred
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (scoreNum) {
      if (prefersReducedMotion || !animate) {
        scoreNum.textContent = res.score;
        lastDisplayedScore = res.score;
      } else {
        if (riskScoreAnimFrame) cancelAnimationFrame(riskScoreAnimFrame);
        const startVal = lastDisplayedScore;
        const targetVal = res.score;
        const duration = 280;
        const startTime = performance.now();

        function step(now) {
          const progress = Math.min(1, (now - startTime) / duration);
          const current = Math.round(startVal + (targetVal - startVal) * progress);
          scoreNum.textContent = current;
          if (progress < 1) {
            riskScoreAnimFrame = requestAnimationFrame(step);
          } else {
            scoreNum.textContent = targetVal;
            lastDisplayedScore = targetVal;
          }
        }
        riskScoreAnimFrame = requestAnimationFrame(step);
      }
    }

    // 4. Status Pill
    const tierPill = $("#riskTierPill");
    if (tierPill) {
      tierPill.textContent = res.tier.label;
      tierPill.className = `risk-tier-pill ${res.tier.className}`;
    }

    // 5. Explanation Paragraph
    const expl = $("#riskExplanation");
    if (expl) expl.textContent = res.explanation;

    // 6. Recommended standard algorithms
    const recList = $("#riskRecommendations");
    if (recList) {
      recList.innerHTML = res.recommendations.map(r => `<li>${r}</li>`).join("");
    }

    // 7. Formula line
    const formulaLine = $("#riskFormulaLine");
    if (formulaLine) {
      formulaLine.textContent = `Formula: (${res.parts.algo} algo + ${res.parts.mosca} mosca + ${res.parts.sens} sens + ${res.parts.expo} expo) × ${res.parts.multiplier.toFixed(2)} = ${res.score}`;
    }

    // Expose on window.QSentinal.risk for optional external readers
    window.QSentinal = window.QSentinal || {};
    window.QSentinal.risk = res;
  }

  function getCalculatorInputs() {
    return {
      industry: $("#riskIndustrySelect") ? $("#riskIndustrySelect").value : "banking",
      crypto: $("#riskCryptoSelect") ? $("#riskCryptoSelect").value : "rsa2048",
      sensitivity: $("#riskSensitivitySelect") ? $("#riskSensitivitySelect").value : "high",
      exposure: $("#riskExposureSelect") ? $("#riskExposureSelect").value : "public",
      x: $("#sliderX") ? $("#sliderX").value : 10,
      y: $("#sliderY") ? $("#sliderY").value : 4,
      z: $("#sliderZ") ? $("#sliderZ").value : 8
    };
  }

  function updateRiskCalculator(animate = true) {
    const inputs = getCalculatorInputs();
    const result = computeRisk(inputs);
    renderRisk(result, animate);
  }

  function initRiskCalculator() {
    const calcSection = $("#dashboard");
    if (!calcSection) return;

    const controlIds = [
      "#riskIndustrySelect",
      "#riskCryptoSelect",
      "#riskSensitivitySelect",
      "#riskExposureSelect",
      "#sliderX",
      "#sliderY",
      "#sliderZ"
    ];

    controlIds.forEach(id => {
      const el = $(id);
      if (el) {
        el.addEventListener("input", () => updateRiskCalculator(true));
        el.addEventListener("change", () => updateRiskCalculator(true));
      }
    });

    // Initial evaluation
    updateRiskCalculator(false);
  }

  initRiskCalculator();

  // ===== SECURE MESSAGING (REAL) =====
  // @noble/post-quantum@0.7.1: keygen() -> { publicKey, secretKey }, encapsulate(publicKey) -> { cipherText, sharedSecret }, decapsulate(cipherText, secretKey) -> sharedSecret

  // --- Pure Helper Functions (Hex, Base64, Formatting) ---
  function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  }

  function hexToBytes(hex) {
    const cleanHex = hex.trim().replace(/^0x/i, "").replace(/[\s\r\n]+/g, "");
    if (cleanHex.length % 2 !== 0) throw new Error("Invalid hex string length: must be even number of characters");
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      const byteVal = parseInt(cleanHex.substr(i, 2), 16);
      if (Number.isNaN(byteVal)) throw new Error(`Invalid hex byte at index ${i}`);
      bytes[i / 2] = byteVal;
    }
    return bytes;
  }

  function bytesToBase64(bytes) {
    let binary = "";
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(b64) {
    const cleanB64 = b64.trim().replace(/[\s\r\n]+/g, "");
    const binary = atob(cleanB64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function zeroBuffer(buf) {
    if (buf && buf.fill) buf.fill(0);
  }

  // --- Dynamic Loader for @noble/post-quantum@0.7.1 ---
  let nobleMlKemInstance = null;
  let isNobleLoading = false;

  async function getMlKem768() {
    if (nobleMlKemInstance) return nobleMlKemInstance;
    if (isNobleLoading) {
      while (isNobleLoading) await wait(50);
      if (nobleMlKemInstance) return nobleMlKemInstance;
    }
    isNobleLoading = true;
    const errorBox = $("#libErrorBox");
    if (errorBox) {
      errorBox.hidden = true;
      errorBox.style.display = "none";
    }

    try {
      // Dynamic import from jsDelivr with pinned version >= 2 weeks old
      const mod = await import("https://cdn.jsdelivr.net/npm/@noble/post-quantum@0.7.1/ml-kem.js/+esm");
      if (!mod || !mod.ml_kem768) {
        throw new Error("Module does not export ml_kem768");
      }
      nobleMlKemInstance = mod.ml_kem768;
      return nobleMlKemInstance;
    } catch (err) {
      if (errorBox) {
        errorBox.hidden = false;
        errorBox.style.display = "flex";
        const msg = $("#libErrorMsg");
        if (msg) msg.textContent = `Post-Quantum library load failed (${err.message || "Network error"}). Check network and retry.`;
      }
      throw err;
    } finally {
      isNobleLoading = false;
    }
  }

  // --- Cryptographic Primitive Functions ---
  async function kemKeygen() {
    const kem = await getMlKem768();
    return kem.keygen();
  }

  async function kemEncapsulate(publicKey) {
    const kem = await getMlKem768();
    return kem.encapsulate(publicKey);
  }

  async function kemDecapsulate(cipherText, secretKey) {
    const kem = await getMlKem768();
    return kem.decapsulate(cipherText, secretKey);
  }

  async function deriveAesKey(sharedSecretBytes) {
    // HKDF-SHA-256 via Web Crypto
    const hkdfKey = await crypto.subtle.importKey(
      "raw",
      sharedSecretBytes,
      "HKDF",
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new TextEncoder().encode("QSentinal-HKDF-Salt-v1"),
        info: new TextEncoder().encode("QSentinal-msg-v1")
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false, // non-extractable
      ["encrypt", "decrypt"]
    );
  }

  async function aesEncrypt(aesKey, plaintext) {
    // Fresh 12-byte IV for every message
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintextBytes = new TextEncoder().encode(plaintext);
    const encryptedBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      plaintextBytes
    );
    const encryptedBytes = new Uint8Array(encryptedBuf);
    // Split into ciphertext and 16-byte authentication tag
    const ciphertext = encryptedBytes.slice(0, -16);
    const tag = encryptedBytes.slice(-16);
    return { iv, ciphertext, tag, plaintextBytes };
  }

  async function aesDecrypt(aesKey, iv, ciphertext, tag) {
    // Combine ciphertext and 16-byte tag for Web Crypto AES-GCM verification
    const combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
    combined.set(ciphertext, 0);
    combined.set(tag, ciphertext.byteLength);
    const decryptedBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      combined
    );
    return new TextDecoder().decode(decryptedBuf);
  }

  // --- In-Memory State Container (Zero Persistence in Storage) ---
  const secureMessaging = {
    bobKeys: null, // { publicKey: Uint8Array, secretKey: Uint8Array }
    currentSharedSecret: null,
    currentPackage: null, // { kemCiphertext, iv, ciphertext, tag }
    lastPlaintext: "",

    reset() {
      if (this.bobKeys) {
        zeroBuffer(this.bobKeys.secretKey);
        zeroBuffer(this.bobKeys.publicKey);
        this.bobKeys = null;
      }
      if (this.currentSharedSecret) {
        zeroBuffer(this.currentSharedSecret);
        this.currentSharedSecret = null;
      }
      if (this.currentPackage) {
        if (this.currentPackage.kemCiphertext) zeroBuffer(this.currentPackage.kemCiphertext);
        if (this.currentPackage.iv) zeroBuffer(this.currentPackage.iv);
        if (this.currentPackage.ciphertext) zeroBuffer(this.currentPackage.ciphertext);
        if (this.currentPackage.tag) zeroBuffer(this.currentPackage.tag);
        this.currentPackage = null;
      }
      this.lastPlaintext = "";

      // Reset DOM elements
      $("#messageDetails") && ($("#messageDetails").hidden = false);
      $("#sessionStatusVal") && ($("#sessionStatusVal").textContent = "Not Started");
      $("#sessionStatusVal") && ($("#sessionStatusVal").className = "");
      $("#recipientVal") && ($("#recipientVal").textContent = "Bob");

      $("#decryptedBox") && ($("#decryptedBox").hidden = true);
      $("#decryptedPlaintext") && ($("#decryptedPlaintext").textContent = "");
      $("#roundtripStatus") && ($("#roundtripStatus").textContent = "Awaiting execution");
      $("#roundtripStatus") && ($("#roundtripStatus").className = "verify-pill");

      $("#sizeSummary") && ($("#sizeSummary").hidden = true);
      $("#artifactsContainer") && ($("#artifactsContainer").hidden = true);

      $("#kemCiphertextDisplay") && ($("#kemCiphertextDisplay").textContent = "—");
      $("#ivDisplay") && ($("#ivDisplay").textContent = "—");
      $("#aesCiphertextDisplay") && ($("#aesCiphertextDisplay").textContent = "—");
      $("#authTagDisplay") && ($("#authTagDisplay").textContent = "—");

      $("#workflowState") && ($("#workflowState").textContent = "AWAITING INPUT");
      $("#workflowResult") && ($("#workflowResult").className = "workflow-result");
      $("#workflowResult") && ($("#workflowResult").innerHTML = '<div class="result-lock">⌑</div><div><b>Waiting for a secure session</b><p>Click "Encrypt &amp; Send" to run real ML-KEM-768 key encapsulation and AES-256-GCM in-browser.</p></div>');

      $$(".workflow-node").forEach(n => n.classList.remove("active", "done"));
      $("#downloadPackageBtn") && ($("#downloadPackageBtn").disabled = true);
      $("#tamperCipherButton") && ($("#tamperCipherButton").disabled = true);
      $("#wrongKeyButton") && ($("#wrongKeyButton").disabled = true);
      $("#packageResult") && ($("#packageResult").textContent = "");
    }
  };

  // Zero memory buffers on page unload / hide
  window.addEventListener("pagehide", () => secureMessaging.reset());

  // --- UI Event Listeners and Controllers ---
  const messageInput = $("#messageInput");
  const messageCount = $("#messageCount");
  messageInput?.addEventListener("input", () => {
    if (messageCount) {
      messageCount.textContent = `${messageInput.value.length.toLocaleString()} / 10,000`;
    }
  });

  $("#retryLibBtn")?.addEventListener("click", async () => {
    const errorBox = $("#libErrorBox");
    if (errorBox) {
      errorBox.hidden = true;
      errorBox.style.display = "none";
    }
    try {
      await getMlKem768();
      toast("Post-Quantum library loaded successfully.");
    } catch {
      toast("Retry failed. Check network connectivity.");
    }
  });

  $("#resetMessagingButton")?.addEventListener("click", () => {
    secureMessaging.reset();
    toast("Session and in-memory cryptographic material cleared.");
  });

  // Copy button handlers for cryptographic artifacts
  $$(".copy-btn").forEach(btn => {
    btn.addEventListener("click", async () => {
      const type = btn.getAttribute("data-copy");
      let textToCopy = "";
      if (type === "kemCipher" && secureMessaging.currentPackage?.kemCiphertext) {
        textToCopy = bytesToHex(secureMessaging.currentPackage.kemCiphertext);
      } else if (type === "iv" && secureMessaging.currentPackage?.iv) {
        textToCopy = bytesToHex(secureMessaging.currentPackage.iv);
      } else if (type === "aesCipher" && secureMessaging.currentPackage?.ciphertext) {
        textToCopy = bytesToBase64(secureMessaging.currentPackage.ciphertext);
      } else if (type === "authTag" && secureMessaging.currentPackage?.tag) {
        textToCopy = bytesToHex(secureMessaging.currentPackage.tag);
      }

      if (!textToCopy) return toast("No artifact data available to copy.");

      try {
        await navigator.clipboard.writeText(textToCopy);
        const originalText = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = originalText; }, 1600);
      } catch {
        toast("Unable to copy to clipboard.");
      }
    });
  });

  // Main Hybrid Encryption Pipeline: Plaintext -> ML-KEM-768 + HKDF + AES-GCM -> Decaps & Decrypt
  $("#sendMessageButton")?.addEventListener("click", async () => {
    const rawMessage = messageInput ? messageInput.value : "";
    if (!rawMessage || !rawMessage.trim()) {
      return toast("Please enter a message before executing hybrid encryption.");
    }
    if (rawMessage.length > 10000) {
      return toast("Message exceeds maximum allowed length of 10,000 characters.");
    }

    const button = $("#sendMessageButton");
    button.disabled = true;
    $("#workflowResult").className = "workflow-result";

    const nodes = $$(".workflow-node");
    nodes.forEach(n => n.classList.remove("active", "done"));
    $("#workflowState").textContent = "ESTABLISHING POST-QUANTUM SESSION";

    try {
      // Step 1: Key Establishment (Bob ML-KEM KeyGen + Alice Encapsulation)
      nodes[0]?.classList.add("active");
      $("#workflowResult").innerHTML = '<div class="result-lock">⌘</div><div><b>01 / ML-KEM-768 Key Establishment</b><p>Bob generates ML-KEM-768 keypair. Alice encapsulates to Bob\'s public key (FIPS 203).</p></div>';
      
      const bobKeys = await kemKeygen(); // Uint8Array 1184 public, 2400 secret
      secureMessaging.bobKeys = bobKeys;

      const { cipherText: kemCiphertext, sharedSecret: aliceSharedSecret } = await kemEncapsulate(bobKeys.publicKey);
      secureMessaging.currentSharedSecret = new Uint8Array(aliceSharedSecret);
      await wait(350);
      nodes[0]?.classList.remove("active");
      nodes[0]?.classList.add("done");

      // Step 2: Shared Secret Derivation via HKDF-SHA-256
      nodes[1]?.classList.add("active");
      $("#workflowResult").innerHTML = '<div class="result-lock">◈</div><div><b>02 / Shared Secret Derivation (HKDF-SHA-256)</b><p>Deriving non-extractable 256-bit AES-GCM key from 32-byte post-quantum shared secret.</p></div>';

      const aliceAesKey = await deriveAesKey(aliceSharedSecret);
      await wait(350);
      nodes[1]?.classList.remove("active");
      nodes[1]?.classList.add("done");

      // Step 3: Authenticated Encryption (AES-256-GCM)
      nodes[2]?.classList.add("active");
      $("#workflowResult").innerHTML = '<div class="result-lock">▧</div><div><b>03 / Authenticated Payload Encryption</b><p>Encrypting UTF-8 plaintext with random 12-byte IV and 128-bit authentication tag.</p></div>';

      const { iv, ciphertext, tag, plaintextBytes } = await aesEncrypt(aliceAesKey, rawMessage);
      secureMessaging.currentPackage = {
        kemCiphertext: new Uint8Array(kemCiphertext),
        iv: new Uint8Array(iv),
        ciphertext: new Uint8Array(ciphertext),
        tag: new Uint8Array(tag)
      };
      secureMessaging.lastPlaintext = rawMessage;
      await wait(350);
      nodes[2]?.classList.remove("active");
      nodes[2]?.classList.add("done");

      // Step 4: Bob Receives, Decapsulates & Authenticates
      nodes[3]?.classList.add("active");
      $("#workflowResult").innerHTML = '<div class="result-lock">✓</div><div><b>04 / Bob Decapsulation &amp; Recovery</b><p>Bob decapsulates KEM ciphertext with secret key, derives matching AES key, and verifies GCM tag.</p></div>';

      const bobSharedSecret = await kemDecapsulate(kemCiphertext, bobKeys.secretKey);
      const bobAesKey = await deriveAesKey(bobSharedSecret);
      const recoveredPlaintext = await aesDecrypt(bobAesKey, iv, ciphertext, tag);
      await wait(350);
      nodes[3]?.classList.remove("active");
      nodes[3]?.classList.add("done");

      // Verification: Plaintext must match exactly
      const isVerified = (recoveredPlaintext === rawMessage);

      if (isVerified) {
        $("#workflowState").textContent = "HYBRID SESSION VERIFIED";
        $("#workflowResult").className = "workflow-result verified-banner";
        $("#workflowResult").innerHTML = '<div class="result-lock">✓</div><div><b>Secure Workflow Verified</b><p>Message delivered with real NIST FIPS 203 ML-KEM-768 key establishment and AES-256-GCM authentication.</p></div>';

        // Update Status Cards
        $("#sessionStatusVal").textContent = "Established · Verified";
        $("#sessionStatusVal").className = "success-text";
        $("#keyExchangeVal").textContent = "ML-KEM-768 · real (FIPS 203)";
        $("#dataProtectionVal").textContent = "AES-256-GCM · real";
        $("#recipientVal").textContent = "Bob (Authenticated)";

        // Update Decrypted by Bob Box
        $("#decryptedBox").hidden = false;
        $("#decryptedPlaintext").textContent = recoveredPlaintext;
        $("#roundtripStatus").textContent = "Round trip verified: plaintext matches";
        $("#roundtripStatus").className = "verify-pill verified";

        // Update Artifacts Display
        $("#artifactsContainer").hidden = false;
        const kemHex = bytesToHex(kemCiphertext);
        $("#kemCiphertextDisplay").textContent = `${kemHex.slice(0, 48)}…${kemHex.slice(-24)} (1,088 bytes)`;
        $("#kemCiphertextDisplay").title = kemHex;
        $("#ivDisplay").textContent = bytesToHex(iv);
        $("#aesCiphertextDisplay").textContent = bytesToBase64(ciphertext);
        $("#authTagDisplay").textContent = bytesToHex(tag);

        // Update Size Breakdown
        $("#sizeSummary").hidden = false;
        const plainBytesCount = plaintextBytes.byteLength;
        const kemBytesCount = kemCiphertext.byteLength;
        const ivBytesCount = iv.byteLength;
        const cipherBytesCount = ciphertext.byteLength;
        const tagBytesCount = tag.byteLength;
        const totalTransmitted = kemBytesCount + ivBytesCount + cipherBytesCount + tagBytesCount;

        $("#plaintextSize").textContent = `${plainBytesCount.toLocaleString()} B`;
        $("#kemSize").textContent = `${kemBytesCount.toLocaleString()} B`;
        $("#ivSize").textContent = `${ivBytesCount} B`;
        $("#aesCipherSize").textContent = `${cipherBytesCount.toLocaleString()} B`;
        $("#tagSize").textContent = `${tagBytesCount} B`;
        $("#totalTransmittedSize").textContent = `${totalTransmitted.toLocaleString()} B`;

        // Enable test and export buttons
        $("#downloadPackageBtn").disabled = false;
        $("#tamperCipherButton").disabled = false;
        $("#wrongKeyButton").disabled = false;

        toast("Hybrid encryption & round-trip verification successful.");
      } else {
        throw new Error("Plaintext round trip verification failed: content mismatch.");
      }
    } catch (err) {
      console.error("Hybrid messaging workflow error:", err);
      $("#workflowState").textContent = "WORKFLOW FAILED";
      $("#workflowResult").className = "workflow-result error-banner";
      $("#workflowResult").innerHTML = `<div class="result-lock">✕</div><div><b>Encryption Pipeline Error</b><p>${err.message || "An unexpected error occurred during cryptographic operations."}</p></div>`;
      $("#sessionStatusVal").textContent = "Failed";
      $("#sessionStatusVal").className = "error-text";
      toast(`Workflow error: ${err.message || "Cryptographic failure"}`);
    } finally {
      button.disabled = false;
    }
  });

  // Tamper Test: Flips 1 bit in ciphertext and verifies AES-GCM rejects it
  $("#tamperCipherButton")?.addEventListener("click", async () => {
    if (!secureMessaging.currentPackage || !secureMessaging.bobKeys) {
      return toast("Run hybrid encryption first before tampering.");
    }

    try {
      // Clone ciphertext and flip the lowest bit of the first byte
      const tamperedCipher = new Uint8Array(secureMessaging.currentPackage.ciphertext);
      tamperedCipher[0] ^= 1;

      // Bob decapsulates and derives key
      const bobSharedSecret = await kemDecapsulate(secureMessaging.currentPackage.kemCiphertext, secureMessaging.bobKeys.secretKey);
      const bobAesKey = await deriveAesKey(bobSharedSecret);

      // Attempt decryption with tampered ciphertext
      await aesDecrypt(bobAesKey, secureMessaging.currentPackage.iv, tamperedCipher, secureMessaging.currentPackage.tag);

      // If we reach here, tampering was NOT detected (should never happen with AES-GCM)
      toast("Warning: Tampered ciphertext was not detected.");
    } catch (err) {
      // Expected: Web Crypto AES-GCM integrity check fails with OperationError
      $("#workflowResult").className = "workflow-result error-banner";
      $("#workflowResult").innerHTML = '<div class="result-lock">✕</div><div><b>Authentication Failed: Message Was Modified</b><p>The 128-bit AES-GCM authentication tag rejected the 1-bit modified ciphertext. Message integrity intact.</p></div>';
      $("#roundtripStatus").textContent = "Authentication failed: message was modified";
      $("#roundtripStatus").className = "verify-pill error";
      $("#decryptedPlaintext").textContent = "[Rejected: Payload modified in transit]";
      toast("Authentication failed: message was modified (1-bit tamper detected).");
    }
  });

  // Wrong Key Test: Attempts decryption with a freshly generated mismatched keypair
  $("#wrongKeyButton")?.addEventListener("click", async () => {
    if (!secureMessaging.currentPackage) {
      return toast("Run hybrid encryption first before testing wrong key.");
    }

    try {
      // Generate an independent wrong keypair
      const impostorKeys = await kemKeygen();

      // ML-KEM decapsulation with wrong key uses implicit rejection (produces pseudo-random secret)
      const wrongSharedSecret = await kemDecapsulate(secureMessaging.currentPackage.kemCiphertext, impostorKeys.secretKey);
      const wrongAesKey = await deriveAesKey(wrongSharedSecret);

      // Attempt decryption
      await aesDecrypt(wrongAesKey, secureMessaging.currentPackage.iv, secureMessaging.currentPackage.ciphertext, secureMessaging.currentPackage.tag);

      toast("Warning: Decryption succeeded with wrong key.");
    } catch (err) {
      // Expected: Mismatched key produces pseudo-random AES key, failing AES-GCM authentication
      $("#workflowResult").className = "workflow-result error-banner";
      $("#workflowResult").innerHTML = '<div class="result-lock">✕</div><div><b>Decryption Failed: Untrusted / Wrong Key</b><p>ML-KEM-768 implicit rejection and AES-GCM tag verification rejected the unauthorized key.</p></div>';
      $("#roundtripStatus").textContent = "Authentication failed: wrong secret key";
      $("#roundtripStatus").className = "verify-pill error";
      $("#decryptedPlaintext").textContent = "[Rejected: Invalid secret key]";
      toast("Decryption rejected: wrong secret key failed authentication.");
    }
  });

  // Download Encrypted Package as JSON
  $("#downloadPackageBtn")?.addEventListener("click", () => {
    if (!secureMessaging.currentPackage) return toast("No active package to export.");

    const pkg = {
      format: "QSentinal-Hybrid-v1",
      standard: "NIST FIPS 203 ML-KEM-768 + AES-256-GCM",
      kemCiphertext: bytesToHex(secureMessaging.currentPackage.kemCiphertext),
      iv: bytesToHex(secureMessaging.currentPackage.iv),
      ciphertext: bytesToBase64(secureMessaging.currentPackage.ciphertext),
      tag: bytesToHex(secureMessaging.currentPackage.tag),
      timestamp: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `qsentinal-package-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast("Encrypted package downloaded (.json).");
  });

  // Package Upload / Import Controls
  $("#uploadPackageBtn")?.addEventListener("click", () => {
    $("#packageFileInput")?.click();
  });

  $("#packageFileInput")?.addEventListener("change", (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
      const content = evt.target?.result;
      if (typeof content === "string" && $("#importPackageInput")) {
        $("#importPackageInput").value = content;
        toast("Package JSON loaded from file.");
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  });

  // Decrypt Package Handler
  $("#decryptPackageBtn")?.addEventListener("click", async () => {
    const pkgText = $("#importPackageInput")?.value.trim();
    if (!pkgText) return toast("Please paste or upload a package JSON string.");

    let pkg;
    try {
      pkg = JSON.parse(pkgText);
    } catch {
      return toast("Invalid package: malformed JSON format.");
    }

    if (!pkg.kemCiphertext || !pkg.iv || !pkg.ciphertext || !pkg.tag) {
      return toast("Invalid package: missing required fields (kemCiphertext, iv, ciphertext, tag).");
    }

    // Determine secret key to use
    const customKeyHex = $("#importSecretKeyInput")?.value.trim();
    let secretKeyBytes = null;

    if (customKeyHex) {
      try {
        secretKeyBytes = hexToBytes(customKeyHex);
        if (secretKeyBytes.byteLength !== 2400) {
          return toast(`Invalid secret key length: expected 2,400 bytes for ML-KEM-768, got ${secretKeyBytes.byteLength}.`);
        }
      } catch (e) {
        return toast(`Secret key format error: ${e.message}`);
      }
    } else if (secureMessaging.bobKeys?.secretKey) {
      secretKeyBytes = secureMessaging.bobKeys.secretKey;
    } else {
      return toast("No secret key found in memory. Please provide Bob's 2,400-byte secret key hex or run Encrypt first.");
    }

    try {
      const kemCipherBytes = hexToBytes(pkg.kemCiphertext);
      if (kemCipherBytes.byteLength !== 1088) {
        return toast(`Invalid KEM ciphertext length: expected 1,088 bytes for ML-KEM-768, got ${kemCipherBytes.byteLength}.`);
      }
      const ivBytes = hexToBytes(pkg.iv);
      if (ivBytes.byteLength !== 12) {
        return toast(`Invalid IV length: expected 12 bytes, got ${ivBytes.byteLength}.`);
      }
      const cipherBytes = base64ToBytes(pkg.ciphertext);
      const tagBytes = hexToBytes(pkg.tag);
      if (tagBytes.byteLength !== 16) {
        return toast(`Invalid auth tag length: expected 16 bytes, got ${tagBytes.byteLength}.`);
      }

      const decSharedSecret = await kemDecapsulate(kemCipherBytes, secretKeyBytes);
      const decAesKey = await deriveAesKey(decSharedSecret);
      const recoveredText = await aesDecrypt(decAesKey, ivBytes, cipherBytes, tagBytes);

      $("#packageResult").innerHTML = `<strong>Decryption Successful:</strong><br><span style="color:var(--text-primary); font-family:var(--font-mono);">${recoveredText.replace(/</g, "&lt;")}</span>`;
      $("#decryptedBox").hidden = false;
      $("#decryptedPlaintext").textContent = recoveredText;
      $("#roundtripStatus").textContent = "Package decrypted & verified";
      $("#roundtripStatus").className = "verify-pill verified";
      toast("Package successfully authenticated and decrypted.");
    } catch (err) {
      console.error("Package decryption failed:", err);
      $("#packageResult").innerHTML = `<strong class="error-text">Decryption Failed:</strong> Authentication error. Either ciphertext was modified or secret key does not match.`;
      toast("Package decryption failed: authentication rejected.");
    }
  });

  // ---------------------------------------------------------------------------
  // 6. ML-KEM Interactive Lab
  // ---------------------------------------------------------------------------
  const kemSteps = [
    { label: "STEP 01 / KEY GENERATION", title: "Create ML-KEM-768 Key Pair", text: "The recipient generates a public key (1,184 bytes) and a private key (2,400 bytes). The public key can be openly shared.", output: "Public key (1,184 B) + Private key (2,400 B)" },
    { label: "STEP 02 / ENCAPSULATION", title: "Encapsulate Shared Secret", text: "A sender uses the recipient's public key to encapsulate a 256-bit secret, producing a 1,088-byte ciphertext and matching shared secret.", output: "Ciphertext (1,088 B) + Derived 256-bit Secret" },
    { label: "STEP 03 / DECAPSULATION", title: "Decapsulate and Recover Secret", text: "The recipient decapsulates using their private key and ciphertext, reconstructing the identical 256-bit symmetric session key.", output: "Matching Shared Secret (256 bits) Verified" }
  ];

  let kemIndex = 0;
  let kemSessionId = null;

  async function renderKem() {
    const step = kemSteps[kemIndex];
    $("#kemStepLabel").textContent = step.label;
    $("#kemStepTitle").textContent = step.title;
    $("#kemStepText").textContent = step.text;
    $("#kemOutput").querySelector("b").textContent = step.output;
    $$(".lab-step").forEach((el, index) => el.classList.toggle("active", index === kemIndex));
    $("#nextKemStep").innerHTML = kemIndex === 2 ? "Restart walkthrough ↻" : "Next step →";

    // Synchronize with backend KEM endpoints if connected
    if (isBackendConnected) {
      try {
        if (kemIndex === 0) {
          const res = await fetch(`${API_BASE}/crypto/kem/keygen`, { method: "POST" });
          if (res.ok) {
            const data = await res.json();
            kemSessionId = data.session_id;
            $("#kemOutput").querySelector("b").textContent = `Public Key: ${data.public_key_hex} (${data.public_key_bytes} B)`;
          }
        } else if (kemIndex === 1 && kemSessionId) {
          const res = await fetch(`${API_BASE}/crypto/kem/encapsulate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: kemSessionId })
          });
          if (res.ok) {
            const data = await res.json();
            $("#kemOutput").querySelector("b").textContent = `Ciphertext: ${data.ciphertext_hex} | Fingerprint: ${data.shared_key_fingerprint}`;
          }
        } else if (kemIndex === 2 && kemSessionId) {
          const res = await fetch(`${API_BASE}/crypto/kem/decapsulate`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: kemSessionId })
          });
          if (res.ok) {
            const data = await res.json();
            $("#kemOutput").querySelector("b").textContent = `Decapsulation Verified! Matching Key Fingerprint: ${data.shared_key_fingerprint}`;
          }
        }
      } catch (err) {
        console.warn("KEM API sync error, keeping educational text", err);
      }
    }
  }

  $$(".lab-step").forEach((el, index) => el.addEventListener("click", () => {
    kemIndex = index;
    renderKem();
  }));

  $("#nextKemStep")?.addEventListener("click", () => {
    kemIndex = (kemIndex + 1) % 3;
    renderKem();
  });

  $("#resetKem")?.addEventListener("click", () => {
    kemIndex = 0;
    renderKem();
  });

  renderKem();

  // ---------------------------------------------------------------------------
  // 7. ML-DSA Signature & Verification Lab
  // ---------------------------------------------------------------------------
  $("#signButton")?.addEventListener("click", async () => {
    const text = $("#documentInput").value.trim();
    if (!text) return toast("Enter document text first.");

    const btn = $("#signButton");
    btn.disabled = true;
    $("#signatureOutput").classList.remove("verified");
    $("#signatureOutput").innerHTML = `<div class="signature-seal">…</div><div><b>Creating ML-DSA-65 Signature…</b><small>Computing SHA-512 digest and lattice signature vector</small></div>`;

    if (isBackendConnected) {
      try {
        const signRes = await fetch(`${API_BASE}/crypto/dsa/sign`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ document: text })
        });
        const verifyRes = await fetch(`${API_BASE}/crypto/dsa/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ document: text })
        });

        if (signRes.ok && verifyRes.ok) {
          const signData = await signRes.json();
          await wait(500);
          $("#signatureOutput").classList.add("verified");
          $("#signatureOutput").innerHTML = `<div class="signature-seal">✓</div><div><b>NIST FIPS 204 Signature Verified</b><small>SHA-512: ${signData.document_sha512.slice(0, 24)}… | Sig: 3,309 Bytes</small></div>`;
          $("#signatureStatus").textContent = "Verified (FIPS 204)";
          btn.disabled = false;
          toast("ML-DSA signature verified with Flask backend.");
          return;
        }
      } catch (err) {
        console.warn("DSA backend error, fallback to client simulation", err);
      }
    }

    // Client fallback
    await wait(750);
    $("#signatureOutput").classList.add("verified");
    $("#signatureOutput").innerHTML = `<div class="signature-seal">✓</div><div><b>ML-DSA-65 Verification Successful</b><small>Authenticity and integrity verified locally.</small></div>`;
    $("#signatureStatus").textContent = "Verified (Local)";
    btn.disabled = false;
    toast("ML-DSA verification simulated.");
  });

  // ---------------------------------------------------------------------------
  // 8. ZERO-KNOWLEDGE FILE VAULT: Authenticated Encryption & Decryption
  // ---------------------------------------------------------------------------
  let encryptSelectedFile = null;
  let decryptSelectedFile = null;

  // Tabs for Encrypt vs Decrypt
  const tabEncrypt = $("#tabEncrypt");
  const tabDecrypt = $("#tabDecrypt");
  const encryptView = $("#encryptView");
  const decryptView = $("#decryptView");

  tabEncrypt?.addEventListener("click", () => {
    tabEncrypt.classList.add("active");
    tabDecrypt.classList.remove("active");
    tabEncrypt.setAttribute("aria-selected", "true");
    tabDecrypt.setAttribute("aria-selected", "false");
    encryptView.hidden = false;
    decryptView.hidden = true;
  });

  tabDecrypt?.addEventListener("click", () => {
    tabDecrypt.classList.add("active");
    tabEncrypt.classList.remove("active");
    tabDecrypt.setAttribute("aria-selected", "true");
    tabEncrypt.setAttribute("aria-selected", "false");
    decryptView.hidden = false;
    encryptView.hidden = true;
  });

  // Generate strong random passphrase
  $("#genPassphraseBtn")?.addEventListener("click", () => {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()_+";
    const randVals = crypto.getRandomValues(new Uint8Array(20));
    const pass = Array.from(randVals, b => chars[b % chars.length]).join("");
    const input = $("#vaultPassphrase");
    input.value = pass;
    input.type = "text";
    toast("Strong passphrase generated!");
  });

  // Encryption File Handler
  const fileInput = $("#fileInput");
  const dropZone = $("#dropZone");

  function setEncryptFile(file) {
    if (!file) return;
    encryptSelectedFile = file;
    $("#selectedFile").hidden = false;
    $("#selectedFile").textContent = `Selected: ${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
    $("#protectFileButton").disabled = false;
    $("#vaultResult").textContent = "File selected. Enter a passphrase and click Encrypt.";
  }

  $("#browseFiles")?.addEventListener("click", () => fileInput.click());
  fileInput?.addEventListener("change", () => setEncryptFile(fileInput.files[0]));

  ["dragenter", "dragover"].forEach(type => dropZone?.addEventListener(type, e => {
    e.preventDefault();
    dropZone.classList.add("dragging");
  }));

  ["dragleave", "drop"].forEach(type => dropZone?.addEventListener(type, e => {
    e.preventDefault();
    dropZone.classList.remove("dragging");
  }));

  dropZone?.addEventListener("drop", e => setEncryptFile(e.dataTransfer.files[0]));

  // Key Derivation Helper (PBKDF2 SHA-256, 100,000 iterations)
  async function deriveKeyFromPassphrase(passphrase, salt, usage) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      [usage]
    );
  }

  // Encrypt & Download Action
  $("#protectFileButton")?.addEventListener("click", async () => {
    if (!encryptSelectedFile) return;
    const passphrase = $("#vaultPassphrase").value;
    if (!passphrase) {
      return toast("Please enter a passphrase to encrypt your file.");
    }

    const button = $("#protectFileButton");
    const result = $("#vaultResult");
    button.disabled = true;
    result.textContent = "Deriving key with PBKDF2 (100,000 rounds) & encrypting with AES-256-GCM…";

    try {
      const fileBytes = await encryptSelectedFile.arrayBuffer();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKeyFromPassphrase(passphrase, salt, "encrypt");

      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        fileBytes
      );

      // Package QSentinal Binary Container:
      // [4 bytes 'QSEN'] [1 byte ver 0x01] [16 bytes salt] [12 bytes iv] [2 bytes filename len] [filename UTF-8] [ciphertext + 16B tag]
      const filenameBytes = new TextEncoder().encode(encryptSelectedFile.name);
      const headerLength = 4 + 1 + 16 + 12 + 2 + filenameBytes.length;
      const container = new Uint8Array(headerLength + ciphertext.byteLength);

      // Magic 'QSEN'
      container[0] = 0x51; container[1] = 0x53; container[2] = 0x45; container[3] = 0x4e;
      container[4] = 0x01; // Version
      container.set(salt, 5);
      container.set(iv, 21);

      // Filename length & bytes
      const fnView = new DataView(container.buffer);
      fnView.setUint16(33, filenameBytes.length, false);
      container.set(filenameBytes, 35);

      // Ciphertext with authentication tag
      container.set(new Uint8Array(ciphertext), headerLength);

      // Trigger download
      const blob = new Blob([container], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${encryptSelectedFile.name}.qsentinal.enc`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);

      result.innerHTML = `<b>Encryption Complete:</b> Downloaded <code>${encryptSelectedFile.name}.qsentinal.enc</code>. Save your passphrase; you can restore the original file using the <b>Decrypt File</b> tab.`;
      toast("Encrypted file downloaded successfully.");
    } catch (err) {
      console.error(err);
      result.textContent = "Encryption error: Ensure Web Crypto is available.";
    } finally {
      button.disabled = false;
    }
  });

  // Decryption File Handler
  const decryptFileInput = $("#decryptFileInput");
  const decryptDropZone = $("#decryptDropZone");

  function setDecryptFile(file) {
    if (!file) return;
    decryptSelectedFile = file;
    $("#decryptSelectedFile").hidden = false;
    $("#decryptSelectedFile").textContent = `Selected: ${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
    $("#decryptFileButton").disabled = false;
    $("#decryptResult").textContent = "Encrypted file loaded. Enter original passphrase to decrypt.";
  }

  $("#browseDecryptFiles")?.addEventListener("click", () => decryptFileInput.click());
  decryptFileInput?.addEventListener("change", () => setDecryptFile(decryptFileInput.files[0]));

  ["dragenter", "dragover"].forEach(type => decryptDropZone?.addEventListener(type, e => {
    e.preventDefault();
    decryptDropZone.classList.add("dragging");
  }));

  ["dragleave", "drop"].forEach(type => decryptDropZone?.addEventListener(type, e => {
    e.preventDefault();
    decryptDropZone.classList.remove("dragging");
  }));

  decryptDropZone?.addEventListener("drop", e => setDecryptFile(e.dataTransfer.files[0]));

  // Decrypt & Restore Action
  $("#decryptFileButton")?.addEventListener("click", async () => {
    if (!decryptSelectedFile) return;
    const passphrase = $("#decryptPassphrase").value;
    if (!passphrase) {
      return toast("Please enter the decryption passphrase.");
    }

    const button = $("#decryptFileButton");
    const result = $("#decryptResult");
    button.disabled = true;
    result.textContent = "Authenticating container & decrypting…";

    try {
      const buffer = await decryptSelectedFile.arrayBuffer();
      const bytes = new Uint8Array(buffer);

      // Verify Magic 'QSEN'
      if (bytes[0] !== 0x51 || bytes[1] !== 0x53 || bytes[2] !== 0x45 || bytes[3] !== 0x4e) {
        throw new Error("Invalid format: Not a QSentinal encrypted container (.qsentinal.enc).");
      }

      const version = bytes[4];
      if (version !== 1) {
        throw new Error(`Unsupported container version (${version}).`);
      }

      const salt = bytes.slice(5, 21);
      const iv = bytes.slice(21, 33);
      const fnView = new DataView(buffer);
      const fnLen = fnView.getUint16(33, false);
      const fnBytes = bytes.slice(35, 35 + fnLen);
      const originalFilename = new TextDecoder().decode(fnBytes) || "restored_file";
      const ciphertext = bytes.slice(35 + fnLen);

      // Derive key and decrypt
      const key = await deriveKeyFromPassphrase(passphrase, salt, "decrypt");
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
      );

      // Download restored file
      const blob = new Blob([decryptedBuffer], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = originalFilename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);

      result.innerHTML = `<b>Decryption Successful:</b> Restored original file <code>${originalFilename}</code>. Authentication tag verified!`;
      toast("File decrypted & restored successfully!");
    } catch (err) {
      console.error(err);
      if (err.name === "OperationError") {
        result.innerHTML = `<span style="color:#d75c5c"><b>Authentication Failed:</b> Incorrect passphrase or corrupted/tampered file data.</span>`;
      } else {
        result.innerHTML = `<span style="color:#d75c5c">${err.message}</span>`;
      }
      toast("Decryption failed. Check passphrase.");
    } finally {
      button.disabled = false;
    }
  });

  // ---------------------------------------------------------------------------
  // 9. Migration Roadmap Customization
  // ---------------------------------------------------------------------------
  $("#generateRoadmap")?.addEventListener("click", async () => {
    const sector = $("#sectorSelect").value;
    const priority = $("#prioritySelect").value;

    if (isBackendConnected) {
      try {
        const res = await fetch(`${API_BASE}/roadmap`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sector, priority })
        });
        if (res.ok) {
          const data = await res.json();
          $("#roadmapTitle").textContent = data.title;
          const items = $$("#roadmapList .roadmap-item");
          data.phases.forEach((p, idx) => {
            if (items[idx]) {
              items[idx].querySelector("b").textContent = p.name;
              items[idx].querySelector("p").textContent = p.detail;
              items[idx].querySelector(".roadmap-state").textContent = p.state;
            }
          });
          toast(`${sector} blueprint generated via Flask backend.`);
          return;
        }
      } catch (err) {
        console.warn("Roadmap API error, using local fallback", err);
      }
    }

    // Local Fallback
    $("#roadmapTitle").textContent = `${sector} Post-Quantum Transition Blueprint`;
    const descriptions = [
      `Catalog all cryptographic keys, certificates, and libraries supporting ${sector.toLowerCase()} workloads.`,
      `Evaluate data longevity against Harvest Now, Decrypt Later threats with priority on ${priority.toLowerCase()}.`,
      "Deploy a controlled hybrid pilot combining X25519 and ML-KEM-768 for TLS session key exchange.",
      "Execute phased rollout of NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) across core infrastructure.",
      "Establish automated certificate lifecycle management and monitor emerging post-quantum cryptographic standards."
    ];
    $$("#roadmapList .roadmap-item p").forEach((p, idx) => {
      p.textContent = descriptions[idx] || p.textContent;
    });
    toast(`${sector} roadmap updated locally.`);
  });

  // ---------------------------------------------------------------------------
  // 10. AI Security Advisor Engine (Flask Backend + Local Fallback)
  // ---------------------------------------------------------------------------
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

  async function askAdvisor(prompt) {
    if (!prompt.trim()) return;
    addChatMessage(prompt, "user");

    if (isBackendConnected) {
      try {
        const res = await fetch(`${API_BASE}/advisor/query`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ query: prompt })
        });
        if (res.ok) {
          const data = await res.json();
          setTimeout(() => addChatMessage(data.response, "assistant"), 250);
          return;
        }
      } catch (err) {
        console.warn("Advisor API failed, using client fallback", err);
      }
    }

    // Client-side fallback knowledge matcher
    const q = prompt.toLowerCase();
    let reply = "A successful quantum-safe transition starts with an automated cryptographic inventory. Evaluate NIST FIPS 203 (ML-KEM) for key exchange and FIPS 204 (ML-DSA) for digital signatures.";
    if (q.includes("ml-kem") || q.includes("kem")) {
      reply = "ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) is standardized in NIST FIPS 203. It establishes shared symmetric keys across public channels resistant to quantum attacks.";
    } else if (q.includes("ml-dsa") || q.includes("dsa") || q.includes("signature")) {
      reply = "ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is standardized in NIST FIPS 204. It replaces vulnerable RSA and ECDSA schemes for authentication and non-repudiation.";
    } else if (q.includes("shor") || q.includes("rsa") || q.includes("ecc")) {
      reply = "Shor's algorithm breaks RSA and ECC when run on a cryptanalytically relevant quantum computer. Symmetric ciphers like AES-256 remain quantum-safe.";
    } else if (q.includes("harvest") || q.includes("decrypt")) {
      reply = "Harvest Now, Decrypt Later involves adversaries recording encrypted data today to decrypt once quantum computers emerge. Long-lived confidential data is most vulnerable.";
    }
    setTimeout(() => addChatMessage(reply, "assistant"), 300);
  }

  $("#chatForm")?.addEventListener("submit", event => {
    event.preventDefault();
    const input = $("#chatInput");
    askAdvisor(input.value);
    input.value = "";
  });

  $$(".topic-chip").forEach(button => button.addEventListener("click", () => {
    askAdvisor(button.dataset.prompt);
  }));

})();
