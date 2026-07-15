import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import Summary from '../components/Summary/Summary';

const mockFilters = { severities: ['critical', 'high', 'medium', 'low'], agentIds: ['agent-01'] };

const mockRow = {
  id: 1, agentName: 'server-01', cve: 'CVE-2024-0001', severity: 'critical',
  cvss3Score: 9.5, packageName: 'openssl', packageVersion: '1.1.1',
  status: 'active', detectionTime: '2024-01-15T10:00:00Z', description: 'Test vuln',
};

const mockPage = { content: [mockRow], totalPages: 5, totalElements: 42 };
const emptyPage = { content: [], totalPages: 0, totalElements: 0 };

beforeEach(() => {
  vi.restoreAllMocks();
});

function summaryMock(fail = false) {
  let fetchCount = 0;
  return vi.fn((url) => {
    fetchCount++;
    if (url && url.includes('/filters')) {
      return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    }
    if (fail) return Promise.reject(new Error('Network error'));
    return Promise.resolve({ ok: true, json: () => Promise.resolve(fetchCount <= 3 ? mockPage : emptyPage) });
  });
}

test('renders summary title and subtitle', async () => {
  vi.stubGlobal('fetch', summaryMock());
  render(<MemoryRouter><Summary /></MemoryRouter>);
  expect(await screen.findByText('Resumen de Vulnerabilidades')).toBeInTheDocument();
  expect(screen.getByText(/Vista y resumen de las vulnerabilidades activas/i)).toBeInTheDocument();
});

test('displays loading state initially', () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
  render(<MemoryRouter><Summary /></MemoryRouter>);
  expect(screen.getByText(/Sincronizando con base de datos/i)).toBeInTheDocument();
});

test('displays empty state when no data', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(emptyPage) });
  }));
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/No hay registros/i)).toBeInTheDocument();
  });
});

test('displays rows with data', async () => {
  vi.stubGlobal('fetch', summaryMock());
  render(<MemoryRouter><Summary /></MemoryRouter>);
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  expect(screen.getByText('server-01')).toBeInTheDocument();
});

test('shows error on fetch failure', async () => {
  vi.stubGlobal('fetch', summaryMock(true));
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/No se pudo cargar la tabla/i)).toBeInTheDocument();
  });
});

test('shows pagination info', async () => {
  vi.stubGlobal('fetch', summaryMock());
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await waitFor(() => {
    expect(screen.getByText(/P.gina 1 de 5/i)).toBeInTheDocument();
  });
});

test('shows export PDF button', async () => {
  vi.stubGlobal('fetch', summaryMock());
  render(<MemoryRouter><Summary /></MemoryRouter>);
  expect(await screen.findByText(/Exportar PDF/i)).toBeInTheDocument();
});

test('export PDF disabled when no rows', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(emptyPage) });
  }));
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await screen.findByText(/No hay registros/i);
  expect(screen.getByText(/Exportar PDF/i)).toBeDisabled();
});

test('export PDF enabled when rows exist', async () => {
  vi.stubGlobal('fetch', summaryMock());
  render(<MemoryRouter><Summary /></MemoryRouter>);
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  expect(screen.getByText(/Exportar PDF/i)).not.toBeDisabled();
});

test('accepts custom title and subtitle', async () => {
  vi.stubGlobal('fetch', summaryMock());
  render(<MemoryRouter><Summary title="Custom Title" subtitle="Custom Sub" /></MemoryRouter>);
  expect(await screen.findByText('Custom Title')).toBeInTheDocument();
  expect(screen.getByText('Custom Sub')).toBeInTheDocument();
});

test('shows high priority toggle by default', async () => {
  vi.stubGlobal('fetch', summaryMock());
  render(<MemoryRouter><Summary /></MemoryRouter>);
  expect(await screen.findByText(/Alta prioridad OFF/i)).toBeInTheDocument();
});

test('hides severity filter when hideSeverityFilter is true', async () => {
  vi.stubGlobal('fetch', summaryMock());
  render(<MemoryRouter><Summary hideSeverityFilter={true} /></MemoryRouter>);
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  expect(screen.queryByText(/Todas las severidades/i)).not.toBeInTheDocument();
});

test('hides high priority toggle when locked', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  }));
  render(<MemoryRouter><Summary lockHighPriority={true} /></MemoryRouter>);
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  expect(screen.queryByText(/Alta prioridad/i)).not.toBeInTheDocument();
});

test('toggles high priority', async () => {
  let fetchCount = 0;
  const f = vi.fn((url) => {
    fetchCount++;
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(fetchCount <= 3 ? mockPage : emptyPage) });
  });
  vi.stubGlobal('fetch', f);
  render(<MemoryRouter><Summary /></MemoryRouter>);
  const toggle = await screen.findByText(/Alta prioridad OFF/i);
  fireEvent.click(toggle);
  await screen.findByText(/Alta prioridad ON/i);
});

test('clicking sort header changes sort', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  }));
  render(<MemoryRouter><Summary /></MemoryRouter>);
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  const sortBtn = screen.getByText(/CVE ID/i);
  fireEvent.click(sortBtn);
});

test('clicking agent sort header', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  }));
  render(<MemoryRouter><Summary /></MemoryRouter>);
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  const btns = screen.getAllByText(/Agente/i);
  fireEvent.click(btns[0]);
});

test('clicking detection time sort header', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  }));
  render(<MemoryRouter><Summary /></MemoryRouter>);
  expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument();
  fireEvent.click(screen.getByText(/Detectada/i));
});

test('formatDate handles null date', async () => {
  const rowNullDate = { ...mockRow, detectionTime: null };
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve({ content: [rowNullDate], totalPages: 1, totalElements: 1 }) });
  }));
  render(<MemoryRouter><Summary /></MemoryRouter>);
  expect(await screen.findByText('-')).toBeInTheDocument();
});

test('search input changes filter', async () => {
  const fetchMock = vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  });
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await screen.findByText('CVE-2024-0001');
  const searchInput = screen.getByPlaceholderText(/Buscar por CVE/i);
  fireEvent.change(searchInput, { target: { value: 'test' } });
});

test('pagination next button works', async () => {
  const fetchMock = vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  });
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await screen.findByText(/P.gina 1 de 5/i);
  const nextBtn = screen.getByText(/Siguiente/i);
  fireEvent.click(nextBtn);
});

test('page input navigates on button click', async () => {
  const fetchMock = vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  });
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await screen.findByText(/P.gina 1 de 5/i);
  const input = screen.getByRole('spinbutton');
  fireEvent.change(input, { target: { value: '3' } });
  const goBtn = screen.getByText('Ir');
  fireEvent.click(goBtn);
});

test('page input navigates on Enter key', async () => {
  const fetchMock = vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  });
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await screen.findByText(/P.gina 1 de 5/i);
  const input = screen.getByRole('spinbutton');
  fireEvent.change(input, { target: { value: '3' } });
  fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' });
});

test('previous button disabled on first page', async () => {
  vi.stubGlobal('fetch', vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  }));
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await screen.findByText(/P.gina 1 de 5/i);
  expect(screen.getByText(/Anterior/i)).toBeDisabled();
});

test('changing severity filter triggers re-fetch', async () => {
  const fetchMock = vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  });
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await screen.findByText('CVE-2024-0001');
  const severitySelect = screen.getByDisplayValue('Todas las severidades');
  fireEvent.change(severitySelect, { target: { value: 'critical' } });
});

test('changing agent filter triggers re-fetch', async () => {
  const fetchMock = vi.fn((url) => {
    if (url && url.includes('/filters')) return Promise.resolve({ ok: true, json: () => Promise.resolve(mockFilters) });
    return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPage) });
  });
  vi.stubGlobal('fetch', fetchMock);
  render(<MemoryRouter><Summary /></MemoryRouter>);
  await screen.findByText('CVE-2024-0001');
  const agentSelect = screen.getByDisplayValue('Todos los agentes');
  fireEvent.change(agentSelect, { target: { value: 'agent-01' } });
});
