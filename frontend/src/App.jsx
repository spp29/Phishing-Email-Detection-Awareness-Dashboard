import { useEffect, useState } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [activeTab, setActiveTab] = useState("analyze");

  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [urls, setUrls] = useState("");
  const [attachments, setAttachments] = useState("");

  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    phishing: 0,
    suspicious: 0,
    legitimate: 0,
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    loadStats();
    loadHistory();
  }, []);

  const loadStats = async () => {
    try {
      const response = await fetch(`${API_URL}/stats`);
      if (response.ok) {
        const data = await response.json();
        setStats(data);
      }
    } catch (err) {
      console.log("Stats unavailable:", err);
    }
  };

  const loadHistory = async () => {
    try {
      const response = await fetch(`${API_URL}/history`);
      if (response.ok) {
        const data = await response.json();
        setHistory(data.analyses || []);
      }
    } catch (err) {
      console.log("History unavailable:", err);
    }
  };

  const analyzeEmail = async (e) => {
    e.preventDefault();

    setLoading(true);
    setError("");
    setResult(null);

    const urlList = urls
      .split("\n")
      .map((url) => url.trim())
      .filter(Boolean);

    const attachmentList = attachments
      .split("\n")
      .map((file) => file.trim())
      .filter(Boolean);

    const emailData = {
      sender,
      subject,
      body,
      urls: urlList,
      attachments: attachmentList,
    };

    try {
      const response = await fetch(`${API_URL}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(emailData),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Unable to analyze email");
      }

      setResult(data);

      await loadStats();
      await loadHistory();
    } catch (err) {
      setError(
        `${err.message}. Make sure the FastAPI backend is running on port 8000.`
      );
    } finally {
      setLoading(false);
    }
  };

  const clearForm = () => {
    setSender("");
    setSubject("");
    setBody("");
    setUrls("");
    setAttachments("");
    setResult(null);
    setError("");
  };

  const getRiskClass = (level) => {
    if (!level) return "";
    return level.toLowerCase();
  };

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div>
            <div className="brand">
              <span className="shield">🛡️</span>
              <div>
                <h1>Phishing Email Detection</h1>
                <p>Security Awareness Dashboard</p>
              </div>
            </div>
          </div>

          <div className="status">
            <span className="status-dot"></span>
            API Connected
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="nav">
        <button
          className={activeTab === "analyze" ? "nav-btn active" : "nav-btn"}
          onClick={() => setActiveTab("analyze")}
        >
          🔍 Analyze Email
        </button>

        <button
          className={activeTab === "history" ? "nav-btn active" : "nav-btn"}
          onClick={() => setActiveTab("history")}
        >
          📋 History
        </button>

        <button
          className={activeTab === "stats" ? "nav-btn active" : "nav-btn"}
          onClick={() => setActiveTab("stats")}
        >
          📊 Statistics
        </button>

        <button
          className={activeTab === "awareness" ? "nav-btn active" : "nav-btn"}
          onClick={() => setActiveTab("awareness")}
        >
          🎓 Awareness
        </button>
      </nav>

      <main className="container">
        {/* Dashboard Statistics */}
        <section className="stats-grid">
          <div className="stat-card">
            <span className="stat-icon">📧</span>
            <div>
              <p>Total Analyses</p>
              <h2>{stats.total || 0}</h2>
            </div>
          </div>

          <div className="stat-card danger">
            <span className="stat-icon">🚨</span>
            <div>
              <p>Likely Phishing</p>
              <h2>{stats.phishing || 0}</h2>
            </div>
          </div>

          <div className="stat-card warning">
            <span className="stat-icon">⚠️</span>
            <div>
              <p>Suspicious</p>
              <h2>{stats.suspicious || 0}</h2>
            </div>
          </div>

          <div className="stat-card safe">
            <span className="stat-icon">✅</span>
            <div>
              <p>Likely Legitimate</p>
              <h2>{stats.legitimate || 0}</h2>
            </div>
          </div>
        </section>

        {/* Analyze */}
        {activeTab === "analyze" && (
          <section className="content-grid">
            <div className="card form-card">
              <div className="card-header">
                <div>
                  <h2>Analyze an Email</h2>
                  <p>
                    Enter the email details below. The system checks the
                    sender, content, URLs and attachments for phishing
                    indicators.
                  </p>
                </div>
              </div>

              <form onSubmit={analyzeEmail}>
                <label>Sender Email</label>
                <input
                  type="email"
                  placeholder="example@company.com"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  required
                />

                <label>Subject</label>
                <input
                  type="text"
                  placeholder="Enter email subject"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  required
                />

                <label>Email Body</label>
                <textarea
                  rows="7"
                  placeholder="Paste the email content here..."
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  required
                />

                <label>URLs</label>
                <textarea
                  rows="4"
                  placeholder="Enter one URL per line."
                  value={urls}
                  onChange={(e) => setUrls(e.target.value)}
                />

                <label>Attachments</label>
                <textarea
                  rows="3"
                  placeholder="Enter one filename per line."
                  value={attachments}
                  onChange={(e) => setAttachments(e.target.value)}
                />

                <div className="form-buttons">
                  <button className="analyze-btn" type="submit" disabled={loading}>
                    {loading ? "⏳ Analyzing..." : "🔍 Analyze Email"}
                  </button>

                  <button
                    className="clear-btn"
                    type="button"
                    onClick={clearForm}
                  >
                    Clear
                  </button>
                </div>
              </form>

              {error && <div className="error">{error}</div>}
            </div>

            {/* Result */}
            <div className="card result-card">
              <h2>Analysis Result</h2>

              {!result && (
                <div className="empty-result">
                  <div className="big-icon">🛡️</div>
                  <h3>No analysis yet</h3>
                  <p>
                    Submit an email to see its phishing risk assessment.
                  </p>
                </div>
              )}

              {result && (
                <div className="result">
                  <div
                    className={`risk-circle ${getRiskClass(
                      result.risk_level
                    )}`}
                  >
                    <strong>{result.risk_score}</strong>
                    <span>/100</span>
                  </div>

                  <h3>{result.classification}</h3>

                  <div
                    className={`risk-badge ${getRiskClass(
                      result.risk_level
                    )}`}
                  >
                    Risk Level: {result.risk_level}
                  </div>

                  <h4>Findings</h4>

                  {result.findings && result.findings.length > 0 ? (
                    <div className="findings">
                      {result.findings.map((finding, index) => (
                        <div className="finding" key={index}>
                          <div className="finding-top">
                            <strong>{finding.type}</strong>
                            <span
                              className={`severity ${getRiskClass(
                                finding.severity
                              )}`}
                            >
                              {finding.severity}
                            </span>
                          </div>
                          <p>{finding.message}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="safe-message">
                      ✅ No suspicious indicators were detected.
                    </p>
                  )}

                  <div className="analysis-meta">
                    <span>
                      URLs analyzed: {result.analysis_summary?.urls_analyzed ?? 0}
                    </span>
                    <span>
                      Attachments analyzed:{" "}
                      {result.analysis_summary?.attachments_analyzed ?? 0}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </section>
        )}

        {/* History */}
        {activeTab === "history" && (
          <section className="card">
            <h2>📋 Analysis History</h2>
            <p className="section-description">
              Previously analyzed emails stored by the backend.
            </p>

            {history.length === 0 ? (
              <div className="empty-result">
                <div className="big-icon">📭</div>
                <h3>No analysis history</h3>
                <p>Analyze an email first and it will appear here.</p>
              </div>
            ) : (
              <div className="history-list">
                {history.map((item, index) => (
                  <div className="history-item" key={item.id || index}>
                    <div>
                      <strong>{item.subject || "No subject"}</strong>
                      <p>{item.sender || "Unknown sender"}</p>
                    </div>

                    <span
                      className={`history-badge ${getRiskClass(
                        item.risk_level
                      )}`}
                    >
                      {item.classification || item.risk_level}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {/* Statistics */}
        {activeTab === "stats" && (
          <section className="card">
            <h2>📊 Statistics</h2>
            <p className="section-description">
              Overview of analyzed email classifications.
            </p>

            <div className="large-stats">
              <div>
                <span>Total</span>
                <strong>{stats.total || 0}</strong>
              </div>

              <div>
                <span>Likely Phishing</span>
                <strong>{stats.phishing || 0}</strong>
              </div>

              <div>
                <span>Suspicious</span>
                <strong>{stats.suspicious || 0}</strong>
              </div>

              <div>
                <span>Likely Legitimate</span>
                <strong>{stats.legitimate || 0}</strong>
              </div>
            </div>
          </section>
        )}

        {/* Awareness */}
        {activeTab === "awareness" && (
          <section className="card awareness">
            <h2>🎓 Phishing Awareness</h2>

            <div className="awareness-grid">
              <div>
                <h3>🔗 Check suspicious links</h3>
                <p>
                  Be careful with links that use unusual domains, HTTP instead
                  of HTTPS, or misleading website names.
                </p>
              </div>

              <div>
                <h3>🔐 Protect your credentials</h3>
                <p>
                  Never provide passwords, OTPs or sensitive account
                  information through unexpected email requests.
                </p>
              </div>

              <div>
                <h3>🚨 Watch for urgency</h3>
                <p>
                  Messages demanding immediate action, verification or payment
                  can be common phishing indicators.
                </p>
              </div>

              <div>
                <h3>📎 Be careful with attachments</h3>
                <p>
                  Do not open unexpected attachments, especially executable or
                  suspicious file types.
                </p>
              </div>
            </div>
          </section>
        )}
      </main>

      <footer>
        <p>
          🛡️ Phishing Email Detection & Awareness Dashboard
        </p>
        <span>Defensive educational security tool</span>
      </footer>
    </div>
  );
}

export default App;