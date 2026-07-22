import { useState, useEffect, useRef } from 'react';
import { Database, Plus, Trash2, ArrowLeft, Send, Loader2, CheckCircle, AlertCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import './Consumer.css';

const API_BASE_URL = import.meta.env.VITE_API_URL;

const Consumer = () => {
    const navigate = useNavigate();
    const userId = localStorage.getItem('user_id');
    const parsedUserId = Number.parseInt(userId, 10);
    
    const [servers, setServers] = useState([{ id: 1, ip: '', credentialId: '' }]);
    const [availableCredentials, setAvailableCredentials] = useState([]);
    const [nextServerId, setNextServerId] = useState(2);    
    const [loading, setLoading] = useState(false);
    const [progressCount, setProgressCount] = useState(0);
    const [totalTarget, setTotalTarget] = useState(0);
    const [taskId, setTaskId] = useState(null);
    const [notification, setNotification] = useState({ message: '', type: '' });
    const eventSourceRef = useRef(null);

    // Cargar credenciales disponibles
    useEffect(() => {
        const fetchCredentials = async () => {
            if (!userId) return;
            try {
                const response = await fetch(`${API_BASE_URL}/api/infra-credentials/user/${parsedUserId}`);
                if (response.ok) {
                    const data = await response.json();
                    setAvailableCredentials(data);
                }
            } catch (error) {
                console.error('Error cargando credenciales:', error);
            }
        };
        fetchCredentials();
    }, [userId]);

    // SSE: progreso en tiempo real
    useEffect(() => {
        if (taskId && loading) {
            const eventSource = new EventSource(`${API_BASE_URL}/api/vulns/progress/${taskId}`);
            eventSourceRef.current = eventSource;

            eventSource.addEventListener('progress', (e) => {
                const data = JSON.parse(e.data);
                setProgressCount(data.processed);
                setTotalTarget(data.total);
            });

            eventSource.addEventListener('complete', () => {
                setLoading(false);
                setTaskId(null);
                eventSource.close();
                setNotification({ message: 'Sincronización completada', type: 'success' });
                setTimeout(() => setNotification({ message: '', type: '' }), 5000);
            });

            eventSource.addEventListener('error', (err) => {
                console.error('SSE error:', err);
                setLoading(false);
                setTaskId(null);
                eventSource.close();
                setNotification({ message: 'Error en la sincronización', type: 'error' });
                setTimeout(() => setNotification({ message: '', type: '' }), 5000);
            });

            return () => {
                eventSource.close();
            };
        }
    }, [taskId, loading]);

    const addServer = () => {
        setServers((prev) => [...prev, { id: nextServerId, ip: '', credentialId: '' }]);
        setNextServerId((id) => id + 1);
    };

    const removeServer = (id) => {
        if (servers.length > 1) {
            setServers((prev) => prev.filter((s) => s.id !== id));
        }
    };

    const handleInputChange = (id, field, value) => {
        setServers((prev) =>
            prev.map((s) => (s.id === id ? { ...s, [field]: value } : s))
        );
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setProgressCount(0);
        setTotalTarget(0);
        setNotification({ message: '', type: '' });
        
        const appAuth = localStorage.getItem('auth_basic');
        
        try {
            for (const server of servers) {
                // 1. Obtener el total de vulnerabilidades NUEVAS (no el global)
                const countRes = await fetch(`${API_BASE_URL}/api/vulns/remote-new-count`, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': appAuth
                    },
                    body: JSON.stringify({
                        ip: server.ip,
                        infrastructureCredentialId: Number.parseInt(server.credentialId)
                    })
                });
                const countData = await countRes.json();
                const newCount = countData.newCount || 0;
                setTotalTarget(prev => prev + newCount);

                // 2. Llamar al consumo (solo si hay novedades)
                if (newCount > 0) {
                    const consumeRes = await fetch(`${API_BASE_URL}/api/vulns/consume`, {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json',
                            'Authorization': appAuth 
                        },
                        body: JSON.stringify({
                            ip: server.ip,
                            infrastructureCredentialId: Number.parseInt(server.credentialId)
                        })
                    });
                    const consumeData = await consumeRes.json();
                    if (consumeData.taskId) {
                        setTaskId(consumeData.taskId);
                    } else if (consumeData.alreadySynced) {
                        setNotification({ message: consumeData.message, type: 'info' });
                        setLoading(false);
                        return;
                    }
                } else {
                    setNotification({ message: 'No hay nuevas vulnerabilidades', type: 'info' });
                    setLoading(false);
                    return;
                }
            }
        } catch (error) {
            console.error("Error:", error);
            setLoading(false);
            setNotification({ message: 'Error al iniciar la sincronización', type: 'error' });
        }
    };

    return (
        <div className="consumer-container">
            <main className="consumer-content-wrapper">
                <header className="consumer-header">
                    <button className="back-button" onClick={() => navigate(-1)} disabled={loading}>
                        <ArrowLeft size={24} />
                    </button>
                    <h1 className="welcome-text">Configuración Wazuh</h1>
                </header>

                <section className="consumer-card">
                    {notification.message && (
                        <div className={`notification ${notification.type}`}>
                            {notification.type === 'success' && <CheckCircle size={20} />}
                            {notification.type === 'error' && <AlertCircle size={20} />}
                            {notification.type === 'info' && <Database size={20} />}
                            <span>{notification.message}</span>
                        </div>
                    )}

                    <div className="db-icon-container">
                        <div className={`icon-wrapper ${loading ? 'spinning-slow' : ''}`}>
                            <Database size={60} />
                        </div>
                        <p className="main-subtitle">
                            {loading 
                                ? "Sincronizando vulnerabilidades nuevas..." 
                                : "Asocia tus servidores con los perfiles de credenciales registrados"}
                        </p>
                    </div>

                    <form onSubmit={handleSubmit} className="wazuh-form">
                        <div className="servers-list">
                            {servers.map((server) => (
                                <div key={server.id} className={`server-row ${loading ? 'row-disabled' : ''}`}>
                                    <div className="input-group">
                                        <label htmlFor={`ip-${server.id}`}>Dirección IP</label>
                                        <input
                                            id={`ip-${server.id}`}
                                            type="text"
                                            disabled={loading}
                                            placeholder="192.168.1.XX"
                                            value={server.ip}
                                            onChange={(e) => handleInputChange(server.id, 'ip', e.target.value)}
                                            required
                                        />
                                    </div>
                                    <div className="input-group">
                                        <label htmlFor={`cred-${server.id}`}>Perfil de Credencial</label>
                                        <select
                                            id={`cred-${server.id}`}
                                            className="cred-select"
                                            disabled={loading}
                                            value={server.credentialId}
                                            onChange={(e) => handleInputChange(server.id, 'credentialId', e.target.value)}
                                            required
                                        >
                                            <option value="">Seleccionar...</option>
                                            {availableCredentials.map(c => (
                                                <option key={c.id} value={c.id}>{c.name}</option>
                                            ))}
                                        </select>
                                    </div>
                                    <div className="actions-group">
                                        {servers.length > 1 && !loading && (
                                            <button type="button" className="remove-btn" onClick={() => removeServer(server.id)}>
                                                <Trash2 size={20} />
                                            </button>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>

                        {!loading && (
                            <button type="button" className="add-server-row-btn" onClick={addServer}>
                                <Plus size={20} />
                                <span>Añadir otro objetivo</span>
                            </button>
                        )}

                        <button type="submit" className={`submit-btn ${loading ? 'loading-active' : ''}`} disabled={loading}>
                            {loading ? (
                                <>
                                    <Loader2 className="spinner" size={20} />
                                    <span>Sincronizando: {progressCount} / {totalTarget}</span>
                                </>
                            ) : (
                                <>
                                    <Send size={20} />
                                    <span>Iniciar Consumo de Datos</span>
                                </>
                            )}
                        </button>
                    </form>
                </section>
            </main>
        </div>
    );
};

export default Consumer;