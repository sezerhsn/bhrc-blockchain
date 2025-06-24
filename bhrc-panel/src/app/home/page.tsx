"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { adminEventTypes } from "../../lib/event_config";
import { FeedbackModal } from "@/components/ui/feedback-modal";

export default function Home() {
  const [events, setEvents] = useState<any[]>([]);
  const [status, setStatus] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);
  const [adminRole, setAdminRole] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [logs, setLogs] = useState<any[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);

  const [modalOpen, setModalOpen] = useState(false);
  const [modalTitle, setModalTitle] = useState("");
  const [modalMessage, setModalMessage] = useState("");

  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

  const fetchOptions = (method: "GET" | "POST") => ({
    method,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    credentials: "include",
  });

  useEffect(() => {
    const checkAdmin = async () => {
      try {
        const res = await fetch("/admin/sessions", fetchOptions("GET"));
        if (res.ok) {
          setIsAdmin(true);
          const tokenPayload = token ? JSON.parse(atob(token.split(".")[1])) : null;
          setAdminRole(tokenPayload?.role || null);
        }
      } catch {
        setIsAdmin(false);
        setAdminRole(null);
      }
    };
    checkAdmin();
  }, []);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retryTimeout: NodeJS.Timeout;

    const connect = () => {
      socket = new WebSocket("ws://157.245.78.23:8080/ws/admin-events");

      socket.onopen = () => console.log("✅ WebSocket bağlantısı kuruldu.");

      socket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        setEvents((prev) => [data, ...prev]);
      };

      socket.onclose = () => {
        console.warn("⚠️ WebSocket bağlantısı koptu. 3 saniye sonra tekrar deneniyor...");
        retryTimeout = setTimeout(connect, 3000);
      };

      socket.onerror = (err) => {
        console.error("❌ WebSocket hatası:", err);
        socket?.close();
      };
    };

    connect();

    return () => {
      if (retryTimeout) clearTimeout(retryTimeout);
      socket?.close();
    };
  }, []);

  useEffect(() => {
    if (!isAdmin) return;

    const fetchLogs = async () => {
      setLogsLoading(true);
      try {
        const res = await fetch("/admin/logs", fetchOptions("GET"));
        if (res.ok) {
          const data = await res.json();
          setLogs(data.logs || []);
        }
      } catch (err) {
        console.warn("Log geçmişi alınamadı:", err);
      } finally {
        setLogsLoading(false);
      }
    };

    fetchLogs();
  }, [isAdmin]);

  const trigger = async (endpoint: string) => {
    setLoading(true);
    try {
      const res = await fetch(`/admin/${endpoint}`, fetchOptions("POST"));
      const json = await res.json();
      setStatus(`✅ ${endpoint}: ${json.message || json.status}`);
      setModalTitle("✅ Başarılı İşlem");
      setModalMessage(json.message || json.status);
    } catch {
      setStatus(`❌ Hata: ${endpoint} çağrısı başarısız oldu.`);
      setModalTitle("❌ Hata Oluştu");
      setModalMessage(`${endpoint} işlemi başarısız oldu.`);
    } finally {
      setLoading(false);
      setModalOpen(true);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    document.cookie = "access_token=; Max-Age=0; path=/;";
    setIsAdmin(false);
    setAdminRole(null);
    setStatus("🚪 Çıkış yapıldı.");
    setModalTitle("🚪 Oturum Sonlandı");
    setModalMessage("Yönetici oturumunuz kapatıldı.");
    setModalOpen(true);
  };

  return (
    <main className="p-6 space-y-6">
      <FeedbackModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title={modalTitle}
        message={modalMessage}
      />

      {isAdmin && (
        <>
          <section>
            <div className="flex justify-between items-center mb-4">
              <h1 className="text-2xl font-bold">🛠️ Admin İşlemleri</h1>
              <Button variant="outline" onClick={handleLogout}>
                🔓 Çıkış Yap
              </Button>
            </div>
            <div className="flex flex-col gap-4">
              {(adminRole === "admin" || adminRole === "super_admin") && (
                <div className="space-y-1">
                  <Button
                    onClick={() => trigger("snapshot")}
                    disabled={loading}
                    className="bg-blue-600 text-white"
                  >
                    {loading ? "İşleniyor..." : "📸 Snapshot Al"}
                  </Button>
                  <span className="text-xs text-gray-500 ml-1">🔑 Rol: Admin ve üzeri</span>
                </div>
              )}

              {adminRole === "super_admin" && (
                <div className="space-y-1">
                  <Button
                    onClick={() => trigger("clear-mempool")}
                    disabled={loading}
                    className="bg-yellow-500 text-white"
                  >
                    {loading ? "İşleniyor..." : "🧹 Mempool Temizle"}
                  </Button>
                  <span className="text-xs text-gray-500 ml-1">🔒 Yalnızca Super Admin</span>
                </div>
              )}

              {adminRole === "super_admin" && (
                <div className="space-y-1">
                  <Button
                    onClick={() => trigger("reset-chain")}
                    disabled={loading}
                    className="bg-red-600 text-white"
                  >
                    {loading ? "İşleniyor..." : "♻️ Zinciri Sıfırla"}
                  </Button>
                  <span className="text-xs text-gray-500 ml-1">⚠️ Kritik işlem — Super Admin yetkisi gerekir</span>
                </div>
              )}
            </div>
            {status && <p className="mt-4 text-green-600 font-mono text-sm">{status}</p>}
          </section>

          <section>
            <h2 className="text-xl font-semibold mb-2">🗂️ Admin İşlem Geçmişi</h2>
            {logsLoading ? (
              <p className="text-sm text-gray-500">⏳ Yükleniyor...</p>
            ) : (
              <ul className="space-y-1 text-sm font-mono max-h-96 overflow-y-auto border rounded p-3 bg-gray-50">
                {logs.map((log, i) => (
                  <li key={i} className="border-b border-dashed pb-1 mb-1">
                    [{new Date(log.timestamp).toLocaleString()}] 👤 {log.user} → {log.action}
                  </li>
                ))}
                {logs.length === 0 && <li className="text-gray-400">Log kaydı bulunamadı.</li>}
              </ul>
            )}
          </section>
        </>
      )}

      <section>
        <h2 className="text-xl font-semibold mb-2">🔔 Canlı Admin Bildirimleri</h2>
        <ul className="space-y-2">
          {events.map((event, i) => {
            const config = adminEventTypes[event.event_type] || {
              label: event.event_type,
              icon: "❔",
              color: "bg-gray-100 text-gray-800",
            };
            return (
              <li key={i} className={`p-3 rounded shadow-sm text-sm flex gap-2 items-start ${config.color}`}>
                <span>{config.icon}</span>
                <div>
                  <div className="font-semibold">{config.label}</div>
                  <div className="text-xs">
                    {typeof window !== "undefined"
                      ? new Date(event.timestamp * 1000).toLocaleString()
                      : ""}
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      </section>
    </main>
  );
}

