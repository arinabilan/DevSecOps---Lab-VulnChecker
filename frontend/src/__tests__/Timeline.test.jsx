import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, test, vi } from 'vitest';
import Timeline from '../components/Timeline/Timeline';

const filtersWithAgents = {
  agentIds: ['100', '200'],
  severities: ['critical', 'high'],
  packageTypes: ['openssl', 'kernel'],
};

const filtersWithoutAgents = { agentIds: [], severities: [], packageTypes: [] };

const timelinePage = {
  content: [
    {
      cve: 'CVE-2024-0001',
      severity: 'critical',
      cvss3Score: 9.8,
      packageType: 'openssl',
      timeline: [
        { startDate: '2024-01-10T00:00:00Z' },
        { startDate: '2024-02-01T00:00:00Z', endDate: '2024-03-15T00:00:00Z' },
      ],
    },
    { cve: 'CVE-2024-0002', severity: 'high', timeline: [] },
  ],
  totalPages: 3,
  totalElements: 25,
};

const emptyPage = { content: [], totalPages: 1, totalElements: 0 };

const zeroRangePage = {
  content: [
    {
      cve: 'CVE-ZERO-1',
      severity: 'critical',
      timeline: [{ startDate: '2030-01-01T00:00:00Z' }],
    },
  ],
  totalPages: 1,
  totalElements: 1,
};

const ongoingPage = {
  content: [
    {
      cve: 'CVE-ONGOING',
      severity: 'critical',
      timeline: [{ startDate: '2024-01-01T00:00:00Z' }],
    },
  ],
  totalPages: 1,
  totalElements: 1,
};

function timelineMock({ filters = filtersWithAgents, page = timelinePage, filtersMode, pageMode } = {}) {
  return vi.fn((url) => {
    if (url && url.includes('/filters')) {
      if (filtersMode === 'network') return Promise.reject(new Error('Network error'));
      if (filtersMode === 'http') return Promise.resolve({ ok: false, status: 500 });
      return Promise.resolve({ ok: true, json: () => Promise.resolve(filters) });
    }
    if (url && url.includes('/timeline')) {
      if (pageMode === 'network') return Promise.reject(new Error('Network error'));
      if (pageMode === 'http') return Promise.resolve({ ok: false, status: 500 });
      return Promise.resolve({ ok: true, json: () => Promise.resolve(page) });
    }
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
  });
}

const renderTimeline = () => render(<MemoryRouter><Timeline /></MemoryRouter>);

beforeEach(() => {
  vi.restoreAllMocks();
});

test('shows loading state initially', () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
  renderTimeline();
  expect(screen.getByText(/Sincronizando línea de tiempo/i)).toBeInTheDocument();
});

test('stays loading when filters have no agents', async () => {
  const fetchMock = timelineMock({ filters: filtersWithoutAgents });
  vi.stubGlobal('fetch', fetchMock);
  renderTimeline();
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/filters'));
  });
  expect(screen.getByText(/Sincronizando línea de tiempo/i)).toBeInTheDocument();
  const refreshBtn = screen.getByRole('button', { name: /cargando/i });
  expect(refreshBtn).toBeDisabled();
  const calls = fetchMock.mock.calls.filter(c => c[0] && c[0].includes('/timeline'));
  expect(calls.length).toBe(0);
});

test('auto-selects first agent and loads timeline', async () => {
  const fetchMock = timelineMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTimeline();
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  expect(screen.getByText('CVE-2024-0002')).toBeInTheDocument();
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('wazuhAgentId=100'));
  });
});

test('renders month markers and pagination footer', async () => {
  const { container } = renderTimelineWithMock(timelineMock());
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  const markers = container.querySelectorAll('.timeline-month-marker');
  expect(markers.length).toBeGreaterThan(0);
  expect(markers[0].textContent).toMatch(/\/\d{4}/);
  expect(screen.getByText(/Mostrando 2 de 25/i)).toBeInTheDocument();
  expect(screen.getByText(/Página 1 de 3/i)).toBeInTheDocument();
});

test('marks ongoing intervals', async () => {
  const { container } = renderTimelineWithMock(timelineMock({ page: ongoingPage }));
  await screen.findByText('CVE-ONGOING');
  const bars = container.querySelectorAll('.timeline-bar');
  const ongoing = Array.from(bars).find(b => b.classList.contains('ongoing'));
  expect(ongoing).toBeTruthy();
  expect(ongoing.getAttribute('title')).toContain('Activa');
});

test('handles zero-range timeline axis', async () => {
  const { container } = renderTimelineWithMock(timelineMock({ page: zeroRangePage }));
  await screen.findByText('CVE-ZERO-1');
  expect(container.querySelectorAll('.timeline-month-marker').length).toBeGreaterThan(0);
});

test('shows empty message when no rows', async () => {
  vi.stubGlobal('fetch', timelineMock({ page: emptyPage }));
  renderTimeline();
  expect(await screen.findByText(/No hay registros para los filtros seleccionados/i)).toBeInTheDocument();
});

test('shows error when timeline HTTP fails', async () => {
  vi.stubGlobal('fetch', timelineMock({ pageMode: 'http' }));
  renderTimeline();
  expect(await screen.findByText(/No se pudo cargar la evolución desde el backend/i)).toBeInTheDocument();
});

test('shows error when timeline network fails', async () => {
  vi.stubGlobal('fetch', timelineMock({ pageMode: 'network' }));
  renderTimeline();
  expect(await screen.findByText(/No se pudo cargar la evolución desde el backend/i)).toBeInTheDocument();
});

test('shows error when filters fail', async () => {
  vi.stubGlobal('fetch', timelineMock({ filtersMode: 'network' }));
  renderTimeline();
  expect(await screen.findByText(/Error al cargar los filtros/i)).toBeInTheDocument();
});

test('ignores filters HTTP failure silently', async () => {
  vi.stubGlobal('fetch', timelineMock({ filtersMode: 'http' }));
  renderTimeline();
  await waitFor(() => {
    expect(fetch).toHaveBeenCalledWith(expect.stringContaining('/filters'));
  });
  expect(screen.queryByText(/Error al cargar los filtros/i)).not.toBeInTheDocument();
});

test('refresh button refetches', async () => {
  const fetchMock = timelineMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTimeline();
  await screen.findByText('CVE-2024-0001');
  const before = fetchMock.mock.calls.filter(c => c[0] && c[0].includes('/timeline')).length;
  fireEvent.click(screen.getByText(/Actualizar/i));
  await waitFor(() => {
    const after = fetchMock.mock.calls.filter(c => c[0] && c[0].includes('/timeline')).length;
    expect(after).toBeGreaterThan(before);
  });
});

test('filter changes trigger refetch with params', async () => {
  const fetchMock = timelineMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTimeline();
  await screen.findByText('CVE-2024-0001');

  const agentSelect = screen.getByDisplayValue('Agente 100');
  fireEvent.change(agentSelect, { target: { value: '200' } });
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('wazuhAgentId=200'));
  });

  const severitySelect = screen.getByDisplayValue(/Severidad \(Todas\)/i);
  fireEvent.change(severitySelect, { target: { value: 'high' } });
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('severity=high'));
  });

  const packageSelect = screen.getByDisplayValue(/Paquete \(Todos\)/i);
  fireEvent.change(packageSelect, { target: { value: 'kernel' } });
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('packageType=kernel'));
  });

  const cvssInputs = screen.getAllByPlaceholderText('Min');
  fireEvent.change(cvssInputs[0], { target: { value: '5' } });
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('cvssMin=5'));
  });

  const cvssMaxInput = screen.getByPlaceholderText('Max');
  fireEvent.change(cvssMaxInput, { target: { value: '8' } });
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('cvssMax=8'));
  });
});

test('pagination controls work', async () => {
  const fetchMock = timelineMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTimeline();
  await screen.findByText('CVE-2024-0001');

  const next = screen.getByText(/Siguiente/i);
  const prev = screen.getByText(/Anterior/i);
  expect(prev).toBeDisabled();
  fireEvent.click(next);
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('page=1'));
  });
  await waitFor(() => {
    expect(prev).not.toBeDisabled();
  });
  fireEvent.click(prev);
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('page=0'));
  });
});

test('page input Enter and Ir navigate and clamp', async () => {
  const fetchMock = timelineMock();
  vi.stubGlobal('fetch', fetchMock);
  const { container } = renderTimeline();
  await screen.findByText('CVE-2024-0001');

  const input = container.querySelector('.pagination-go input');
  fireEvent.change(input, { target: { value: '2' } });
  fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('page=1'));
  });

  fireEvent.change(input, { target: { value: '99' } });
  fireEvent.click(screen.getByText('Ir'));
  await waitFor(() => {
    const calls = fetchMock.mock.calls.filter(c => c[0] && c[0].includes('/timeline'));
    expect(calls.some(c => c[0].includes('page=2'))).toBe(true);
  });

  fireEvent.change(input, { target: { value: 'abc' } });
  fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
  expect(input.value).toBe('');
});

function renderTimelineWithMock(mock) {
  vi.stubGlobal('fetch', mock);
  return renderTimeline();
}
