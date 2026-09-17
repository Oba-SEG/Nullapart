import { Mail, AlertTriangle, CheckCircle, Activity } from "lucide-react";
import "./Dashboard.css";

export function Dashboard() {
  return (
    <div className="dashboard">
      <h1 className="page-title">Dashboard</h1>

      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-icon">
            <Mail size={24} />
          </div>
          <div className="metric-content">
            <span className="metric-value">1,234</span>
            <span className="metric-label">Messages Today</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon warning">
            <AlertTriangle size={24} />
          </div>
          <div className="metric-content">
            <span className="metric-value">12</span>
            <span className="metric-label">Quarantined</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon success">
            <CheckCircle size={24} />
          </div>
          <div className="metric-content">
            <span className="metric-value">98.5%</span>
            <span className="metric-label">Delivery Rate</span>
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-icon">
            <Activity size={24} />
          </div>
          <div className="metric-content">
            <span className="metric-value">45</span>
            <span className="metric-label">Queue Depth</span>
          </div>
        </div>
      </div>

      <div className="dashboard-sections">
        <section className="card">
          <h2 className="section-title">Recent Activity</h2>
          <div className="activity-list">
            <div className="activity-item">
              <span className="activity-time">2 min ago</span>
              <span className="activity-text">
                Message TX-abc123 delivered to customer-a@example.com
              </span>
            </div>
            <div className="activity-item">
              <span className="activity-time">5 min ago</span>
              <span className="activity-text">
                Message TX-def456 quarantined - malware detected
              </span>
            </div>
            <div className="activity-item">
              <span className="activity-time">10 min ago</span>
              <span className="activity-text">
                Message TX-ghi789 delivered to customer-b@example.com
              </span>
            </div>
          </div>
        </section>

        <section className="card">
          <h2 className="section-title">System Health</h2>
          <div className="health-list">
            <div className="health-item">
              <span className="health-status healthy"></span>
              <span>Postfix</span>
              <span className="health-detail">Running</span>
            </div>
            <div className="health-item">
              <span className="health-status healthy"></span>
              <span>Rspamd</span>
              <span className="health-detail">Running</span>
            </div>
            <div className="health-item">
              <span className="health-status healthy"></span>
              <span>Mail Core</span>
              <span className="health-detail">Running</span>
            </div>
            <div className="health-item">
              <span className="health-status healthy"></span>
              <span>Database</span>
              <span className="health-detail">Connected</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
