import React, { useEffect, useState, useCallback } from 'react';
import { AlertCircle, RefreshCcw, Activity } from 'lucide-react';
import './Timeline.css';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';
const API_URL = `${API_BASE_URL}/api/vulnerabilities/timeline`;
const FILTERS_URL = `${API_BASE_URL}/api/vulnerabilities/filters`;
const PAGE_SIZE = 12;

const Timeline = () => {
    const [rows, setRows] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    
    // Filtros
    const [agentFilter, setAgentFilter] = useState('');
    const [severityFilter, setSeverityFilter] = useState('all');
    const [packageTypeFilter, setPackageTypeFilter] = useState('all');
    const [cvssMin, setCvssMin] = useState(0);
    const [cvssMax, setCvssMax] = useState(10);
    
    // Opciones de filtros desde el backend
    const [agentOptions, setAgentOptions] = useState([]);
    const [severityOptions, setSeverityOptions] = useState([]);
    const [packageTypeOptions, setPackageTypeOptions] = useState([]);

    // Paginación
    const [currentPage, setCurrentPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);
    const [totalRecords, setTotalRecords] = useState(0);
    const [pageInput, setPageInput] = useState('');

    // Eje de tiempo
    const [timeAxis, setTimeAxis] = useState({ min: 0, max: 0, range: 0, months: [] });

    // 1. Cargar metadatos para los filtros
    useEffect(() => {
        const loadFilters = async () => {
            try {
                const res = await fetch(FILTERS_URL);
                if (!res.ok) return;
                const json = await res.json();
                setAgentOptions(Array.isArray(json?.agentIds) ? json.agentIds : []);
                setSeverityOptions(Array.isArray(json?.severities) ? json.severities : []);
                setPackageTypeOptions(Array.isArray(json?.packageTypes) ? json.packageTypes : []);
                
                // Forzar la selección del primer agente si existe
                if (json?.agentIds?.length > 0) {
                    setAgentFilter(json.agentIds[0]);
                }
            } catch {
                setError('Error al cargar los filtros.');
            }
        };
        loadFilters();
    }, []);

    // 2. Calcular límites del eje X en base a los datos
    const calculateTimeAxis = (data) => {
        if (!data || data.length === 0) return;
        
        const now = Date.now();
        let minDate = now;
        let maxDate = now;

        data.forEach(row => {
            row.timeline?.forEach(interval => {
                const start = new Date(interval.startDate).getTime();
                const end = interval.endDate ? new Date(interval.endDate).getTime() : now;
                if (start < minDate) minDate = start;
                if (end > maxDate) maxDate = end;
            });
        });

        // Dar un pequeño margen (5%) a los lados
        const padding = (maxDate - minDate) * 0.05;
        minDate -= padding;
        maxDate += padding;
        
        // Evitar división por cero si solo hay un evento o el rango es 0
        if (maxDate === minDate) {
            minDate -= 86400000 * 30; // -1 mes
            maxDate += 86400000 * 30; // +1 mes
        }

        const range = maxDate - minDate;

        // Generar marcas de meses para el eje superior
        const months = [];
        const d = new Date(minDate);
        d.setDate(1); // Ir al inicio del mes
        while (d.getTime() <= maxDate) {
            months.push({
                label: `${String(d.getMonth() + 1).padStart(2, '0')}/${d.getFullYear()}`,
                pos: ((d.getTime() - minDate) / range) * 100
            });
            d.setMonth(d.getMonth() + 1);
        }

        setTimeAxis({ min: minDate, max: maxDate, range, months });
    };

    // 3. Obtener datos
    const fetchTimeline = useCallback(async () => {
        if (!agentFilter) return; // Esperar a tener un agente seleccionado

        setLoading(true);
        setError('');
        try {
            const params = new URLSearchParams();
            params.set('page', String(currentPage - 1));
            params.set('size', String(PAGE_SIZE));
            params.set('wazuhAgentId', agentFilter);
            
            if (severityFilter !== 'all') params.set('severity', severityFilter);
            if (packageTypeFilter !== 'all') params.set('packageType', packageTypeFilter);
            params.set('cvssMin', cvssMin);
            params.set('cvssMax', cvssMax);

            const response = await fetch(`${API_URL}?${params.toString()}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const data = await response.json();
            const content = data.content || [];

            setRows(content);
            setTotalPages(data.totalPages || 1);
            setTotalRecords(data.totalElements || content.length);
            calculateTimeAxis(content);
        } catch {
            setError('No se pudo cargar la evolución desde el backend.');
        } finally {
            setLoading(false);
        }
    }, [currentPage, agentFilter, severityFilter, packageTypeFilter, cvssMin, cvssMax]);

    useEffect(() => { fetchTimeline(); }, [fetchTimeline]);
    useEffect(() => { setCurrentPage(1); }, [agentFilter, severityFilter, packageTypeFilter, cvssMin, cvssMax]);

    return (
        <div className="tables-container">
            <main className="tables-content">
                <header className="tables-header">
                    <div>
                        <h1>Evolución</h1>
                        <p>Línea de tiempo de vulnerabilidades por agente.</p>
                    </div>
                    <div className="tables-header-actions">
                        <button className="refresh-button" onClick={fetchTimeline} disabled={loading || !agentFilter}>
                            <RefreshCcw size={16} className={loading ? 'animate-spin' : ''} />
                            {loading ? 'Cargando...' : 'Actualizar'}
                        </button>
                    </div>
                </header>

                <section className="tables-filters compact">
                    <select value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)}>
                        <option value="" disabled>Seleccione un agente...</option>
                        {agentOptions.map((a) => <option key={a} value={a}>Agente {a}</option>)}
                    </select>
                    
                    <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
                        <option value="all">Severidad (Todas)</option>
                        {severityOptions.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>

                    <select value={packageTypeFilter} onChange={(e) => setPackageTypeFilter(e.target.value)}>
                        <option value="all">Paquete (Todos)</option>
                        {packageTypeOptions.map((p) => <option key={p} value={p}>{p}</option>)}
                    </select>

                    <div className="cvss-filter-group">
                        <span>CVSS3:</span>
                        <input type="number" min="0" max="10" step="0.1" value={cvssMin} onChange={(e) => setCvssMin(e.target.value)} placeholder="Min" />
                        <span>-</span>
                        <input type="number" min="0" max="10" step="0.1" value={cvssMax} onChange={(e) => setCvssMax(e.target.value)} placeholder="Max" />
                    </div>
                </section>

                {error && (
                    <div className="tables-error">
                        <AlertCircle size={18} /> <span>{error}</span>
                    </div>
                )}

                <section className="tables-card">
                    {loading ? (
                        <div className="tables-state">Sincronizando línea de tiempo...</div>
                    ) : rows.length === 0 ? (
                        <div className="tables-state">No hay registros para los filtros seleccionados.</div>
                    ) : (
                        <div className="timeline-wrapper">
                            {/* Eje X (Meses) */}
                            <div className="timeline-header-row">
                                <div className="timeline-cve-column">CVE ID</div>
                                <div className="timeline-grid-column">
                                    {timeAxis.months.map((month, idx) => (
                                        <div key={idx} className="timeline-month-marker" style={{ left: `${month.pos}%` }}>
                                            <div className="month-label">{month.label}</div>
                                            {/* Eliminamos el div month-line de aquí */}
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Filas de CVEs */}
                            <div className="timeline-body" style={{ position: 'relative' }}>
                                {/* Capa de guías verticales exactas (Reemplaza el hack del CSS) */}
                                <div style={{ position: 'absolute', top: 0, left: '180px', right: 0, bottom: 0, pointerEvents: 'none', zIndex: 0 }}>
                                    {timeAxis.months.map((month, idx) => (
                                        <div 
                                            key={`guide-${idx}`} 
                                            style={{ 
                                                position: 'absolute', 
                                                left: `${month.pos}%`, 
                                                top: 0, 
                                                bottom: 0, 
                                                borderLeft: '1px dashed #444' 
                                            }} 
                                        />
                                    ))}
                                </div>

                                {rows.map((row) => (
                                    <div className="timeline-row" key={row.cve} style={{ position: 'relative', zIndex: 1 }}>
                                        <div className="timeline-cve-column">
                                            <Activity size={14} className="cve-icon" />
                                            {row.cve}
                                        </div>
                                        <div className="timeline-grid-column">
                                            {row.timeline?.map((interval, idx) => {
                                                const start = new Date(interval.startDate).getTime();
                                                const end = interval.endDate ? new Date(interval.endDate).getTime() : Date.now();
                                                
                                                // Calcular posiciones en porcentaje
                                                const left = ((start - timeAxis.min) / timeAxis.range) * 100;
                                                const width = ((end - start) / timeAxis.range) * 100;

                                                return (
                                                    <div 
                                                        key={idx} 
                                                        className={`timeline-bar ${!interval.endDate ? 'ongoing' : ''}`}
                                                        style={{ left: `${left}%`, width: `${width}%` }}
                                                        title={`Severidad: ${row.severity || '-'}\nCVSS3: ${row.cvss3Score ?? '-'}\nTipo de paquete: ${row.packageType || '-'}\nInicio: ${new Date(interval.startDate).toLocaleDateString()}\nFin: ${interval.endDate ? new Date(interval.endDate).toLocaleDateString() : 'Activa'}`}
                                                    />
                                                );
                                            })}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    <footer className="tables-footer">
                        <span>Mostrando {rows.length} de {totalRecords}</span>
                        <div className="pagination-controls">
                            <button onClick={() => setCurrentPage(p => Math.max(p - 1, 1))} disabled={currentPage === 1}>Anterior</button>
                            <span>Página {currentPage} de {totalPages}</span>
                            <button onClick={() => setCurrentPage(p => Math.min(p + 1, totalPages))} disabled={currentPage === totalPages}>Siguiente</button>
                            
                            <label className="pagination-go">
                                <span>Ir a</span>
                                <input
                                    type="number"
                                    value={pageInput}
                                    onChange={(e) => setPageInput(e.target.value)}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter') {
                                            const n = Number.parseInt(pageInput, 10);
                                            if (!Number.isNaN(n)) setCurrentPage(Math.max(1, Math.min(n, totalPages)));
                                            setPageInput('');
                                        }
                                    }}
                                />
                                <button
                                    type="button"
                                    onClick={() => {
                                        const n = Number.parseInt(pageInput, 10);
                                        if (!Number.isNaN(n)) setCurrentPage(Math.max(1, Math.min(n, totalPages)));
                                        setPageInput('');
                                    }}
                                >
                                    Ir
                                </button>
                            </label>
                        </div>
                    </footer>
                </section>
            </main>
        </div>
    );
};

export default Timeline;