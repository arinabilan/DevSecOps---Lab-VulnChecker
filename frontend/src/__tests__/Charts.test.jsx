import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, test, vi } from 'vitest';
import Charts from '../components/Charts/Charts';

const mockStats = {
  total: 100,
  category: [{ name: 'critical', value: 30 }],
  severity: [{ name: 'high', value: 40 }],
  cve: [{ name: 'CVE-2024-0001', value: 10 }],
  package: [{ name: 'openssl', value: 5 }],
  agent: [{ name: 'server-01', value: 20 }],
};

const emptyStats = { total: 0, category: [], severity: [], cve: [], package: [], agent: [] };

beforeEach(() => {
  vi.restoreAllMocks();
});

test('displays loading state initially', () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  expect(screen.getByText(/Cargando graficos/i)).toBeInTheDocument();
});

test('displays empty state when no data', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(emptyStats) })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/No hay datos para construir graficos/i)).toBeInTheDocument();
  });
});

test('renders title after loading', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(mockStats) })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  expect(await screen.findByText(/Analisis de Graficos/i)).toBeInTheDocument();
});

test('renders all pie card titles', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(mockStats) })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  expect(await screen.findByText(/Por categoria/i)).toBeInTheDocument();
  expect(screen.getByText(/Por severidad/i)).toBeInTheDocument();
  expect(screen.getByText(/Por codigo CVE/i)).toBeInTheDocument();
  expect(screen.getByText(/Por paquete/i)).toBeInTheDocument();
  expect(screen.getByText(/Por agente/i)).toBeInTheDocument();
});

test('shows pie data items', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(mockStats) })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  expect(await screen.findByText('critical')).toBeInTheDocument();
  expect(screen.getByText('high')).toBeInTheDocument();
  expect(screen.getByText('CVE-2024-0001')).toBeInTheDocument();
  expect(screen.getByText('openssl')).toBeInTheDocument();
  expect(screen.getByText('server-01')).toBeInTheDocument();
});

test('shows empty state for each empty pie card', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve({ total: 10, category: [], severity: [], cve: [], package: [], agent: [] }) })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getAllByText(/No hay datos para mostrar/i).length).toBeGreaterThanOrEqual(5);
  });
});

test('shows error on HTTP failure', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: false, status: 500 })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/No se pudo cargar la informacion para los graficos/i)).toBeInTheDocument();
  });
});

test('shows error on network failure', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.reject(new Error('Network error'))
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/No se pudo cargar la informacion para los graficos/i)).toBeInTheDocument();
  });
});

test('handles null category data', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve({ total: 0, category: null, severity: null, cve: null, package: null, agent: null }) })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/No hay datos para construir graficos/i)).toBeInTheDocument();
  });
});

test('handles items with null name', async () => {
  const data = { total: 5, category: [{ name: null, value: 3 }], severity: [], cve: [], package: [], agent: [] };
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(data) })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  expect(await screen.findByText('Sin dato')).toBeInTheDocument();
});

test('filters out non-numeric and non-positive values', async () => {
  const data = {
    total: 10,
    category: [
      { name: 'KeepMe', value: '30' },
      { name: 'Invalid', value: 'abc' },
      { name: 'Negative', value: -5 },
      { name: 'Zero', value: 0 },
    ],
    severity: [], cve: [], package: [], agent: [],
  };
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(data) })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  expect(await screen.findByText('KeepMe')).toBeInTheDocument();
  expect(screen.queryByText('Invalid')).not.toBeInTheDocument();
  expect(screen.queryByText('Negative')).not.toBeInTheDocument();
  expect(screen.queryByText('Zero')).not.toBeInTheDocument();
});

test('normalizes whitespace-only names to fallback', async () => {
  const data = { total: 5, category: [{ name: '   ', value: 3 }], severity: [], cve: [], package: [], agent: [] };
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(data) })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  expect(await screen.findByText('Sin dato')).toBeInTheDocument();
});

test('treats non-finite total as zero', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve({ ...mockStats, total: 'abc' }) })
  ));
  render(<MemoryRouter><Charts /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/No hay datos para construir graficos/i)).toBeInTheDocument();
  });
});

test('agent card gets wide class', async () => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(mockStats) })
  ));
  const { container } = render(<MemoryRouter><Charts /></MemoryRouter>);
  await screen.findByText('server-01');
  expect(container.querySelector('.pie-card.wide')).toBeTruthy();
});

test('refresh button refetches data', async () => {
  const fetchMock = vi.fn(() =>
    Promise.resolve({ ok: true, json: () => Promise.resolve(mockStats) })
  );
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Charts /></MemoryRouter>);
  await screen.findByText('server-01');
  const before = fetchMock.mock.calls.length;
  fireEvent.click(screen.getByText(/Actualizar/i));
  await waitFor(() => {
    expect(fetchMock.mock.calls.length).toBeGreaterThan(before);
  });
});
