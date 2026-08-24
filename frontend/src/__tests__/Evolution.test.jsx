import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, test, vi } from 'vitest';
import Evolution from '../components/Evolution/Evolution';

const mockFilters = { columnOptions: [2, 3, 4], metrics: ['critical', 'high', 'highCritical', 'total'], agentIds: [] };
const mockPage = {
  content: [{ agentId: 1, agentName: 'server-01', values: {} }],
  columns: [{ key: '2024-01', label: 'Ene 2024' }],
  totalPages: 1, totalRecords: 1,
};
const mockEmptyPage = { content: [], columns: [], totalPages: 0, totalRecords: 0 };

beforeEach(() => {
  vi.restoreAllMocks();
});

function evoMock(page = mockPage) {
  return vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    if (url && url.includes('/evolution')) return Promise.resolve({ ok: true, json: () => Promise.resolve(page) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
  });
}

test('displays loading state initially', () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  expect(screen.getByText(/Cargando matriz/i)).toBeInTheDocument();
});

test('renders title after loading', async () => {
  vi.stubGlobal('fetch', evoMock());
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  expect(await screen.findByText('Evolución')).toBeInTheDocument();
});

test('renders summary cards', async () => {
  vi.stubGlobal('fetch', evoMock());
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  expect(await screen.findByText(/Métrica/i)).toBeInTheDocument();
  expect(screen.getByText(/Agentes en página/i)).toBeInTheDocument();
  expect(screen.getByText(/Snapshots visibles/i)).toBeInTheDocument();
  expect(screen.getByText(/Total agentes/i)).toBeInTheDocument();
});

test('renders metric title as Vulnerabilidades críticas', () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  expect(screen.getAllByText('Vulnerabilidades críticas').length).toBe(2);
});

test('renders empty state when no snapshots', async () => {
  vi.stubGlobal('fetch', evoMock(mockEmptyPage));
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/No hay snapshots disponibles/i)).toBeInTheDocument();
  });
});

test('refreshes on button click', async () => {
  const fetchMock = evoMock();
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText('Evolución');
  const refreshBtn = screen.getByText(/Actualizar/i);
  fireEvent.click(refreshBtn);
});

test('changing metric filter', async () => {
  vi.stubGlobal('fetch', evoMock());
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText('Evolución');
  const selects = screen.getAllByRole('combobox');
  const metricSelect = selects[1];
  fireEvent.change(metricSelect, { target: { value: 'high' } });
  expect(screen.getByDisplayValue(/Vulnerabilidades altas/i)).toBeInTheDocument();
});

test('changing agent filter', async () => {
  vi.stubGlobal('fetch', evoMock());
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText('Evolución');
  const agentSelect = screen.getByDisplayValue('Todos los agentes');
  fireEvent.change(agentSelect, { target: { value: 'all' } });
});

test('changing column count', async () => {
  vi.stubGlobal('fetch', evoMock());
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText('Evolución');
  const selects = screen.getAllByRole('combobox');
  const colSelect = selects[2];
  fireEvent.change(colSelect, { target: { value: '3' } });
  expect(screen.getByDisplayValue(/Últimos 3 snapshots/i)).toBeInTheDocument();
});

test('search input works', async () => {
  vi.stubGlobal('fetch', evoMock());
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText('Evolución');
  const searchInput = screen.getByPlaceholderText(/Buscar por agente/i);
  fireEvent.change(searchInput, { target: { value: 'server' } });
});

test('pagination next button appears', async () => {
  const pageData = {
    content: [{ agentId: 1, agentName: 'srv', values: {} }],
    columns: [{ key: '2024-01', label: 'Ene' }],
    totalPages: 3, totalRecords: 25,
  };
  vi.stubGlobal('fetch', evoMock(pageData));
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  expect(screen.getByText(/Siguiente/i)).not.toBeDisabled();
  expect(screen.getByText(/Anterior/i)).toBeDisabled();
});

test('pagination next click', async () => {
  const pageData = {
    content: [{ agentId: 1, agentName: 'srv', values: {} }],
    columns: [{ key: '2024-01', label: 'Ene' }],
    totalPages: 3, totalRecords: 25,
  };
  const fetchMock = evoMock(pageData);
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  fireEvent.click(screen.getByText(/Siguiente/i));
});

test('pagination page input and go', async () => {
  const pageData = {
    content: [{ agentId: 1, agentName: 'srv', values: {} }],
    columns: [{ key: '2024-01', label: 'Ene' }],
    totalPages: 3, totalRecords: 25,
  };
  const fetchMock = evoMock(pageData);
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  const input = screen.getByRole('spinbutton');
  fireEvent.change(input, { target: { value: '2' } });
  fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
});

test('sorting by column header', async () => {
  const pageData = {
    content: [{ agentId: 1, agentName: 'srv', values: {} }],
    columns: [{ key: '2024-01', label: 'Ene' }],
    totalPages: 1, totalRecords: 1,
  };
  vi.stubGlobal('fetch', evoMock(pageData));
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  const sortBtns = screen.getAllByText(/Último/i);
  fireEvent.click(sortBtns[0]);
});

test('error state shows message', async () => {
  const failingMock = vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.reject(new Error('Network error'));
  });
  vi.stubGlobal('fetch', failingMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/No se pudo cargar la matriz/i)).toBeInTheDocument();
  });
});

test('error on filters API fail', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: false, status: 500 });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  }));
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  expect(await screen.findByText('Evolución')).toBeInTheDocument();
});

test('sort toggle on same column', async () => {
  const pageData = {
    content: [{ agentId: 1, agentName: 'srv', values: {} }],
    columns: [{ key: '2024-01', label: 'Ene' }],
    totalPages: 1, totalRecords: 1,
  };
  vi.stubGlobal('fetch', evoMock(pageData));
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  const sortBtns = screen.getAllByText(/Último/i);
  fireEvent.click(sortBtns[0]);
  fireEvent.click(sortBtns[0]);
});

test('page input click navigates', async () => {
  const pageData = {
    content: [{ agentId: 1, agentName: 'srv', values: {} }],
    columns: [{ key: '2024-01', label: 'Ene' }],
    totalPages: 3, totalRecords: 25,
  };
  vi.stubGlobal('fetch', evoMock(pageData));
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  const input = screen.getByRole('spinbutton');
  fireEvent.change(input, { target: { value: '2' } });
  fireEvent.click(screen.getByText('Ir'));
});

test('agent filter with real agent adds agentId param', async () => {
  const filtersWithAgents = { columnOptions: [2, 3, 4], metrics: ['critical', 'high'], agentIds: [5] };
  const fetchMock = vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(filtersWithAgents) });
    if (url && url.includes('/evolution')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
  });
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText('Evolución');
  const agentSelect = screen.getByDisplayValue('Todos los agentes');
  fireEvent.change(agentSelect, { target: { value: '5' } });
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('agentId=5'));
  });
});

test('resets column count when options exclude current', async () => {
  const filtersOnly23 = { columnOptions: [2, 3], metrics: ['critical'], agentIds: [] };
  const fetchMock = vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(filtersOnly23) });
    if (url && url.includes('/evolution')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
  });
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByDisplayValue(/Últimos 2 snapshots/i)).toBeInTheDocument();
  });
});

test('shows error on HTTP failure', async () => {
  const fetchMock = vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: false, status: 500 });
  });
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  expect(await screen.findByText(/No se pudo cargar la matriz/i)).toBeInTheDocument();
});

test('handles non-array content and columns', async () => {
  const weird = { content: null, columns: null, totalPages: 1, totalElements: 3 };
  vi.stubGlobal('fetch', evoMock(weird));
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/No hay snapshots disponibles/i)).toBeInTheDocument();
  });
});

test('sorting by agent name column', async () => {
  const fetchMock = evoMock();
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  fireEvent.click(screen.getByRole('button', { name: /Nombre/ }));
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('sortKey=agentName'));
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('sortDir=asc'));
  });
});

test('sorting by agent id column', async () => {
  const fetchMock = evoMock();
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  fireEvent.click(screen.getByRole('button', { name: /Agente/ }));
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('sortKey=agentId'));
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('sortDir=asc'));
  });
});

test('sorting by latest value column toggles', async () => {
  const fetchMock = evoMock();
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  fireEvent.click(screen.getByRole('button', { name: /Último/ }));
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('sortKey=latestValue'));
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('sortDir=asc'));
  });
});

test('sort toggle on agent name column', async () => {
  const fetchMock = evoMock();
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  fireEvent.click(screen.getByRole('button', { name: /Nombre/ }));
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('sortDir=asc'));
  });
  fireEvent.click(screen.getByRole('button', { name: /Nombre/ }));
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('sortDir=desc'));
  });
});

test('pagination previous navigates back', async () => {
  const pageData = {
    content: [{ agentId: 1, agentName: 'srv', values: {} }],
    columns: [{ key: '2024-01', label: 'Ene' }],
    totalPages: 3, totalRecords: 25,
  };
  vi.stubGlobal('fetch', evoMock(pageData));
  render(<MemoryRouter><Evolution /></MemoryRouter>);
  await screen.findByText(/Agentes en página/i);
  fireEvent.click(screen.getByText(/Siguiente/i));
  await screen.findByText(/Página 2 de 3/i);
  const prev = screen.getByText(/Anterior/i);
  expect(prev).not.toBeDisabled();
  fireEvent.click(prev);
  await waitFor(() => {
    expect(screen.getByText(/Página 1 de 3/i)).toBeInTheDocument();
  });
});
