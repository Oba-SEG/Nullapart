import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { Search, Filter } from "lucide-react";
import "./Messages.css";

export function Messages() {
  const [search, setSearch] = useState("");

  return (
    <div className="messages-page">
      <div className="page-header">
        <h1 className="page-title">Messages</h1>
        <div className="page-actions">
          <div className="search-box">
            <Search size={18} className="search-icon" />
            <input
              type="text"
              placeholder="Search by ID, sender, or recipient..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="search-input"
            />
          </div>
          <button className="btn">
            <Filter size={16} />
            Filter
          </button>
        </div>
      </div>

      <div className="card">
        <table className="messages-table">
          <thead>
            <tr>
              <th>Transaction ID</th>
              <th>Direction</th>
              <th>Sender</th>
              <th>Recipients</th>
              <th>Status</th>
              <th>Received</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>
                <Link
                  to="/messages/$messageId"
                  params={{ messageId: "TX-001" }}
                  className="message-link"
                >
                  TX-001
                </Link>
              </td>
              <td>
                <span className="badge inbound">Inbound</span>
              </td>
              <td>sender@example.com</td>
              <td>2 recipients</td>
              <td>
                <span className="badge success">Delivered</span>
              </td>
              <td>2026-09-17 08:00</td>
            </tr>
            <tr>
              <td>
                <Link
                  to="/messages/$messageId"
                  params={{ messageId: "TX-002" }}
                  className="message-link"
                >
                  TX-002
                </Link>
              </td>
              <td>
                <span className="badge outbound">Outbound</span>
              </td>
              <td>internal@company.com</td>
              <td>1 recipient</td>
              <td>
                <span className="badge success">Delivered</span>
              </td>
              <td>2026-09-17 07:55</td>
            </tr>
            <tr>
              <td>
                <Link
                  to="/messages/$messageId"
                  params={{ messageId: "TX-003" }}
                  className="message-link"
                >
                  TX-003
                </Link>
              </td>
              <td>
                <span className="badge inbound">Inbound</span>
              </td>
              <td>attacker@evil.com</td>
              <td>1 recipient</td>
              <td>
                <span className="badge warning">Quarantined</span>
              </td>
              <td>2026-09-17 07:50</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
