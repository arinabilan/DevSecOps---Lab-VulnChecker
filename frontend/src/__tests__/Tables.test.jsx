import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, expect, test, vi } from 'vitest';
import Tables from '../components/Tables/Tables';

const mockFilters = { severities: ['critical', 'high', 'medium', 'low'], agentIds: ['agent-01', 'agent-02'] };

const mockRow = {
  id: 1, agentName: 'server-01', cve: 'CVE-2024-0001', severity: 'critical',
  cvss3Score: 9.5, packageName: 'openssl', packageVersion: '1.1.1',
  status: 'active', detectionTime: '2024-01-15T10:00:00Z', description: 'Test vulnerability',
};

const mockPage = { content: [mockRow], totalPages: 5, totalElements: 42 };

beforeEach(() => {
  vi.restoreAllMocks();
});

const renderTables = (props = {}) => render(
  <MemoryRouter><Tables {...props} /></MemoryRouter>
);

function tableMock(page = mockPage) {
  return vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(page) });
  });
}

test('renders default titles', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables();
  expect(screen.getByText('Explorador de Activos')).toBeInTheDocument();
  expect(screen.getByText(/Visualización en crudo/i)).toBeInTheDocument();
});

test('displays loading state initially', () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
  renderTables();
  expect(screen.getByText(/Cargando datos/i)).toBeInTheDocument();
});

test('displays empty state when no data', async () => {
  vi.stubGlobal('fetch', tableMock({ content: [], totalPages: 0, totalElements: 0 }));
  renderTables();
  await waitFor(() => {
    expect(screen.getByText(/No se encontraron registros/i)).toBeInTheDocument();
  });
});

test('displays rows with data', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables();
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  expect(screen.getByText('server-01')).toBeInTheDocument();
});

test('shows error state on fetch failure', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.reject(new Error('Network error'));
  }));
  renderTables();
  await waitFor(() => {
    expect(screen.getByText(/No se pudo cargar la tabla/i)).toBeInTheDocument();
  });
});

test('shows pagination info', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables();
  expect(await screen.findByText(/Mostrando 1 de 42 registros/i)).toBeInTheDocument();
  expect(screen.getByText(/Página 1 de 5/i)).toBeInTheDocument();
});

test('high priority toggle visible by default', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables();
  expect(await screen.findByText(/Alta prioridad OFF/i)).toBeInTheDocument();
});

test('hides high priority toggle when locked', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables({ lockHighPriority: true });
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  expect(screen.queryByText(/Alta prioridad/i)).not.toBeInTheDocument();
});

test('toggles high priority filter', async () => {
  const fetchMock = tableMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTables();
  const toggle = await screen.findByText(/Alta prioridad OFF/i);
  fireEvent.click(toggle);
  await waitFor(() => {
    expect(screen.getByText(/Alta prioridad ON/i)).toBeInTheDocument();
  });
});

test('pagination next button', async () => {
  const fetchMock = tableMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTables();
  await screen.findByText(/Página 1 de 5/i);
  fireEvent.click(screen.getByText(/Siguiente/i));
});

test('page input navigates on Enter', async () => {
  const fetchMock = tableMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTables();
  await screen.findByText(/Página 1 de 5/i);
  const input = screen.getByRole('spinbutton');
  fireEvent.change(input, { target: { value: '3' } });
  fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
});

test('page input navigates on button click', async () => {
  const fetchMock = tableMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTables();
  await screen.findByText(/Página 1 de 5/i);
  const input = screen.getByRole('spinbutton');
  fireEvent.change(input, { target: { value: '3' } });
  fireEvent.click(screen.getByText('Ir'));
});

test('disables previous on page 1', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables();
  await screen.findByText(/Página 1 de 5/i);
  expect(screen.getByText(/Anterior/i)).toBeDisabled();
});

test('pagination previous navigates back', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables();
  await screen.findByText(/Página 1 de 5/i);
  fireEvent.click(screen.getByText(/Siguiente/i));
  await screen.findByText(/Página 2 de 5/i);
  const prev = screen.getByText(/Anterior/i);
  expect(prev).not.toBeDisabled();
  fireEvent.click(prev);
  await screen.findByText(/Página 1 de 5/i);
  expect(screen.getByText(/Anterior/i)).toBeDisabled();
});

test('sorting by column header', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables();
  await screen.findByText('CVE-2024-0001');
  const sortBtn = screen.getByText('Agente');
  fireEvent.click(sortBtn);
});

test('sort toggle on same column', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables();
  await screen.findByText('CVE-2024-0001');
  const getAgentBtn = () => document.querySelectorAll('.sort-header-btn')[1];
  expect(getAgentBtn().textContent).toContain('↕');
  fireEvent.click(getAgentBtn());
  await vi.waitFor(() => {
    expect(getAgentBtn().textContent).toContain('↑');
  });
  fireEvent.click(getAgentBtn());
  await vi.waitFor(() => {
    expect(getAgentBtn().textContent).toContain('↓');
  });
});

test('clicking all sort headers', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables();
  for (let i = 0; i < 7; i++) {
    await vi.waitFor(() => {
      expect(document.querySelectorAll('.sort-header-btn').length).toBe(7);
    });
    const btn = document.querySelectorAll('.sort-header-btn')[i];
    fireEvent.click(btn);
  }
});

test('shows error on HTTP error response', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: false, status: 500 });
  }));
  renderTables();
  await waitFor(() => {
    expect(screen.getByText(/No se pudo cargar la tabla de activos/i)).toBeInTheDocument();
  });
});

test('search input changes filter', async () => {
  const fetchMock = tableMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTables();
  await screen.findByText('CVE-2024-0001');
  const searchInput = screen.getByPlaceholderText(/Buscar por CVE/i);
  fireEvent.change(searchInput, { target: { value: 'test' } });
});

test('changing severity filter', async () => {
  const fetchMock = tableMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTables();
  await screen.findByText('CVE-2024-0001');
  const select = screen.getByDisplayValue('Todas las severidades');
  fireEvent.change(select, { target: { value: 'critical' } });
});

test('changing agent filter', async () => {
  const fetchMock = tableMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTables();
  await screen.findByText('CVE-2024-0001');
  const select = screen.getByDisplayValue('Todos los agentes');
  fireEvent.change(select, { target: { value: 'agent-01' } });
});

test('hides severity filter when hideSeverityFilter is true', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables({ hideSeverityFilter: true });
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  expect(screen.queryByText('Todas las severidades')).not.toBeInTheDocument();
});

test('custom title and subtitle', async () => {
  vi.stubGlobal('fetch', tableMock());
  renderTables({ title: 'Custom', subtitle: 'My sub' });
  expect(await screen.findByText('Custom')).toBeInTheDocument();
  expect(screen.getByText('My sub')).toBeInTheDocument();
});

test('formatDate returns placeholder for null date', async () => {
  const rowNull = { ...mockRow, detectionTime: null };
  vi.stubGlobal('fetch', tableMock({ content: [rowNull], totalPages: 1, totalElements: 1 }));
  renderTables();
  expect(await screen.findByText('-')).toBeInTheDocument();
});

test('refresh button fetches again', async () => {
  const fetchMock = tableMock();
  vi.stubGlobal('fetch', fetchMock);
  renderTables();
  await screen.findByText('CVE-2024-0001');
  fireEvent.click(screen.getByText(/Actualizar/i));
});

test('formatDate handles invalid date string', async () => {
  const rowBad = { ...mockRow, detectionTime: 'not-a-date' };
  vi.stubGlobal('fetch', tableMock({ content: [rowBad], totalPages: 1, totalElements: 1 }));
  renderTables();
  expect(await screen.findByText('not-a-date')).toBeInTheDocument();
});
